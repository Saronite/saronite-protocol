// Copyright (c)      2018, Saronite Protocol
//
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <boost/math/special_functions/round.hpp>

#include "common/int-util.h"
#include "common/round.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"

#undef SARONITE_DEFAULT_LOG_CATEGORY
#define SARONITE_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

#if defined(__x86_64__)
  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    low = mul128(a, b, &high);
  }

#else

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    // __int128 isn't part of the standard, so the previous function wasn't portable. mul128() in Windows is fine,
    // but this portable function should be used elsewhere. Credit for this function goes to latexi95.

    uint64_t aLow = a & 0xFFFFFFFF;
    uint64_t aHigh = a >> 32;
    uint64_t bLow = b & 0xFFFFFFFF;
    uint64_t bHigh = b >> 32;

    uint64_t res = aLow * bLow;
    uint64_t lowRes1 = res & 0xFFFFFFFF;
    uint64_t carry = res >> 32;

    res = aHigh * bLow + carry;
    uint64_t highResHigh1 = res >> 32;
    uint64_t highResLow1 = res & 0xFFFFFFFF;

    res = aLow * bHigh;
    uint64_t lowRes2 = res & 0xFFFFFFFF;
    carry = res >> 32;

    res = aHigh * bHigh + carry;
    uint64_t highResHigh2 = res >> 32;
    uint64_t highResLow2 = res & 0xFFFFFFFF;

    //Addition

    uint64_t r = highResLow1 + lowRes2;
    carry = r >> 32;
    low = (r << 32) | lowRes1;
    r = highResHigh1 + highResLow2 + carry;
    uint64_t d3 = r & 0xFFFFFFFF;
    carry = r >> 32;
    r = highResHigh2 + carry;
    high = d3 | (r << 32);
  }

#endif

  static inline bool cadd(uint64_t a, uint64_t b) {
    return a + b < a;
  }

  static inline bool cadc(uint64_t a, uint64_t b, bool c) {
    return a + b < a || (c && a + b == (uint64_t) -1);
  }

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    uint64_t low, high, top, cur;
    // First check the highest word, this will most likely fail for a random hash.
    mul(swap64le(((const uint64_t *) &hash)[3]), difficulty, top, high);
    if (high != 0) {
      return false;
    }
    mul(swap64le(((const uint64_t *) &hash)[0]), difficulty, low, cur);
    mul(swap64le(((const uint64_t *) &hash)[1]), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul(swap64le(((const uint64_t *) &hash)[2]), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
  }

  // LWMA difficulty algorithm
  // Background:  https://github.com/zawy12/difficulty-algorithms/issues/3
  // Copyright (c) 2017-2018 Zawy (pseudocode)
  // MIT license http://www.opensource.org/licenses/mit-license.php
  // Copyright (c) 2018 Wownero Inc., a Monero Enterprise Alliance partner company
  // Copyright (c) 2018 The Karbowanec developers (initial code)
  // Copyright (c) 2018 Haven Protocol (refinements)
  // Degnr8, Karbowanec, Masari, Bitcoin Gold, Bitcoin Candy, and Haven have contributed.

  // This algorithm is: next_difficulty = harmonic_mean(Difficulties) * T / LWMA(Solvetimes)
  // The harmonic_mean(Difficulties) = 1/average(Targets) so it is also:
  // next_target = avg(Targets) * LWMA(Solvetimes) / T.
  // This is "the best algorithm" because it has lowest root-mean-square error between 
  // needed & actual difficulty during hash attacks while having the lowest standard 
  // deviation during stable hashrate. That is, it's the fastest for a given stability and vice versa.
  // Do not use "if solvetime < 1 then solvetime = 1" which allows a catastrophic exploit.
  // Do not sort timestamps.  "Solvetimes" and "LWMA" variables must allow negatives.
  // Do not use MTP as most recent block.  Do not use (POW)Limits, filtering, or tempering.
  // Do not forget to set N (aka DIFFICULTY_WINDOW in Cryptonote) to recommendation below.
  // The nodes' future time limit (FTL) aka CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT needs to
  // be reduced from 60*60*2 to 500 seconds to prevent timestamp manipulation from miner's with 
  //  > 50% hash power.  If this is too small, it can be increased to 1000 at a cost in protection.

  // Cryptonote clones:  #define DIFFICULTY_BLOCKS_COUNT_V2 DIFFICULTY_WINDOW_V2 + 1


  difficulty_type next_difficulty_v2(std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulative_difficulties, size_t target_seconds) {

    const int64_t T = static_cast<int64_t>(target_seconds);

    size_t N = DIFFICULTY_WINDOW_V2 - 1;

    // Return a difficulty of 1 for first 4 blocks if it's the start of the chain.
    if (timestamps.size() < 4) {
      return 1;
    }
    // Otherwise, use a smaller N if the start of the chain is less than N+1.
    else if ( timestamps.size()-1 < N ) {
      N = timestamps.size() - 1;
    }
    // Otherwise make sure timestamps and cumulative_difficulties are correct size.
    else {
      // TODO: put asserts here, so that the difficulty algorithm is never called with an oversized window
      //       OR make this use the last N+1 timestamps and cum_diff, not the first.
      timestamps.resize(N+1);
      cumulative_difficulties.resize(N+1);
    }
    // To get an average solvetime to within +/- ~0.1%, use an adjustment factor.
    // adjust=0.999 for 80 < N < 120(?)
    const double adjust = 0.998;
    // The divisor k normalizes the LWMA sum to a standard LWMA.
    const double k = N * (N + 1) / 2;

    double LWMA(0), sum_inverse_difficulty(0), harmonic_mean_difficulty(0), nextDifficulty(0);
    int64_t solveTime(0);
    uint64_t difficulty(0), next_difficulty(0);

    // Loop through N most recent blocks. N is most recently solved block.
    for (int64_t i = 1; i <= (int64_t)N; i++) {
      solveTime = static_cast<int64_t>(timestamps[i]) - static_cast<int64_t>(timestamps[i - 1]);
      solveTime = std::min<int64_t>((T * 7), std::max<int64_t>(solveTime, (-7 * T)));
      difficulty = cumulative_difficulties[i] - cumulative_difficulties[i - 1];
      LWMA += (solveTime * i) / k;
      sum_inverse_difficulty += 1 / static_cast<double>(difficulty);
    }

    harmonic_mean_difficulty = N / sum_inverse_difficulty;

    // Keep LWMA sane in case something unforeseen occurs.
    if (static_cast<int64_t>(saronite_round(LWMA)) < T / 20)
      LWMA = static_cast<double>(T / 20);

    nextDifficulty = harmonic_mean_difficulty * T / LWMA * adjust;

    // No limits should be employed, but this is correct way to employ a 20% symmetrical limit:
    // nextDifficulty=max(previous_difficulty*0.8,min(previous_difficulty/0.8, next_difficulty));
    next_difficulty = static_cast<uint64_t>(nextDifficulty);

    if (next_difficulty == 0)
        next_difficulty = 1;

    return next_difficulty;
  }
    difficulty_type next_difficulty_v3(std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulative_difficulties, size_t target_seconds) {	
 uint64_t  T = DIFFICULTY_TARGET_V2;	
uint64_t  N = DIFFICULTY_WINDOW_V2; // N=45, 60, and 90 for T=600, 120, 60.	
uint64_t  L(0), ST, sum_3_ST(0), next_difficulty, prev_difficulty, this_timestamp, previous_timestamp;	
    	
 assert(timestamps.size() == cumulative_difficulties.size() && 	
                 timestamps.size() <= N+1 );	
 // If it's a new coin, do startup code. 	
// Increase difficulty_guess if it needs to be much higher, but guess lower than lowest guess.	
uint64_t difficulty_guess = 100; 	
if (timestamps.size() <= 10 ) {   return difficulty_guess;   }	
if ( timestamps.size() < N +1 ) { N = timestamps.size()-1;  }	
 // If hashrate/difficulty ratio after a fork is < 1/3 prior ratio, hardcode D for N+1 blocks after fork. 	
// difficulty_guess = 100; //  Dev may change.  Guess low.	
// if (height <= UPGRADE_HEIGHT + N+1 ) { return difficulty_guess;  }	
 previous_timestamp = timestamps[0];	
for ( uint64_t i = 1; i <= N; i++) {  	
   if ( timestamps[i] > previous_timestamp  ) {   	
      this_timestamp = timestamps[i];	
   } else {  this_timestamp = previous_timestamp+1;   }	
   ST = std::min(6*T ,this_timestamp - previous_timestamp);	
   previous_timestamp = this_timestamp;	
   L +=  ST * i ; 	
   // delete the following line if you do not want the "jump rule"	
   if ( i > N-3 ) { sum_3_ST += ST; } 	
}	
 next_difficulty = ((cumulative_difficulties[N] - cumulative_difficulties[0])*T*(N+1)*99)/(100*2*L);	
prev_difficulty = cumulative_difficulties[N] - cumulative_difficulties[N-1]; 	
next_difficulty = std::max((prev_difficulty*67)/100, std::min(next_difficulty, (prev_difficulty*150)/100)); 	
 // delete the following line if you do not want the "jump rule"	
if ( sum_3_ST < (8*T)/10) {  next_difficulty = std::max(next_difficulty,(prev_difficulty*108)/100); } 	
 return next_difficulty;	
  }	
// LWMA-4 difficulty algorithm 
// Copyright (c) 2017-2018 Zawy, MIT License
// https://github.com/zawy12/difficulty-algorithms/issues/3
// See commented version for explanations & required config file changes. Fix FTL and MTP!

difficulty_type next_difficulty_v4(std::vector<uint64_t> timestamps, 
   std::vector<difficulty_type> cumulative_difficulties) {
    
   uint64_t  T = DIFFICULTY_TARGET_V2;
   uint64_t  N = DIFFICULTY_WINDOW_V2; // N=45, 60, and 90 for T=600, 120, 60.
   uint64_t  L(0), ST(0), next_difficulty, prev_difficulty, avg_difficulty, i;
        
    assert(timestamps.size() == cumulative_difficulties.size() && timestamps.size() <= N+1 );

   // If it's a new coin, do startup code. Do not remove in case other coins copy your code.
   uint64_t difficulty_guess = 100; 
   if (timestamps.size() <= 12 ) {   return difficulty_guess;   }
   if ( timestamps.size()  < N +1 ) { N = timestamps.size()-1;  }
   
   // If hashrate/difficulty ratio after a fork is < 1/3 prior ratio, hardcode D for N+1 blocks after fork. 
   // This will also cover up a very common type of backwards-incompatible fork.
   // difficulty_guess = 100000; //  Dev may change.  Guess low than anything expected.
   // if ( height <= UPGRADE_HEIGHT + 1 + N ) { return difficulty_guess;  }
 
   // Safely convert out-of-sequence timestamps into > 0 solvetimes.
   std::vector<uint64_t>TS(N+1);
   TS[0] = timestamps[0];
   for ( i = 1; i <= N; i++) {        
      if ( timestamps[i]  > TS[i-1]  ) {   TS[i] = timestamps[i];  } 
      else {  TS[i] = TS[i-1];   }
   }

   for ( i = 1; i <= N; i++) {  
      // Temper long solvetime drops if they were preceded by 3 or 6 fast solves.
      if ( i > 4 && TS[i]-TS[i-1] > 5*T  && TS[i-1] - TS[i-4] < (14*T)/10 ) {   ST = 2*T; }
      else if ( i > 7 && TS[i]-TS[i-1] > 5*T  && TS[i-1] - TS[i-7] < 4*T ) {   ST = 2*T; }
      else { // Assume normal conditions, so get ST.
         // LWMA drops too much from long ST, so limit drops with a 5*T limit 
         ST = std::min(5*T ,TS[i] - TS[i-1]);
      }
      L +=  ST * i ; 
   } 
   if (L < N*N*T/20 ) { L =  N*N*T/20; } 
   avg_difficulty = ( cumulative_difficulties[N] - cumulative_difficulties[0] )/ N;
   
   // Prevent round off error for small D and overflow for large D.
   if (avg_difficulty > 2000000*N*N*T) { 
       next_difficulty = (avg_difficulty/(200*L))*(N*(N+1)*T*97);   
   }   
   else {    next_difficulty = (avg_difficulty*N*(N+1)*T*97)/(200*L);    }

   prev_difficulty =  cumulative_difficulties[N] - cumulative_difficulties[N-1] ; 

   // Apply 10% jump rule.
   if (  ( TS[N] - TS[N-1] < (2*T)/10 ) || 
         ( TS[N] - TS[N-2] < (5*T)/10 ) ||  
         ( TS[N] - TS[N-3] < (8*T)/10 )    )
   {  
       next_difficulty = std::max( next_difficulty, std::min( (prev_difficulty*110)/100, (105*avg_difficulty)/100 ) ); 
   }
   // Make all insignificant digits zero for easy reading.
   i = 1000000000;
   while (i > 1) { 
     if ( next_difficulty > i*100 ) { next_difficulty = ((next_difficulty+i/2)/i)*i; break; }
     else { i /= 10; }
   }
   // Make least 3 digits equal avg of past 10 solvetimes.
   if ( next_difficulty > 100000 ) { 
    next_difficulty = ((next_difficulty+500)/1000)*1000 + std::min(static_cast<uint64_t>(999), (TS[N]-TS[N-10])/10); 
   }
   return  next_difficulty;
}
}