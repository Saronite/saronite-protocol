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

#include "include_base_utils.h"

using namespace epee;

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"

#undef SARONITE_DEFAULT_LOG_CATEGORY
#define SARONITE_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::parse_tpod_from_hex_string(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    switch (nettype) {
      case STAGENET:
        break;
      case TESTNET:
        break;
      case FAKECHAIN:
        break;
      case UNDEFINED:
        break;
      case MAINNET:
		ADD_CHECKPOINT(1,     "e63c594189cc6e4d6f62cb0f81eb973b87b983b9e3aff432ae30b115f5e10d63");
		ADD_CHECKPOINT(150,     "40cf1fc3f9c423f35c883f934521bd6fd93fa63382d77f04fef6113cf9d6a887");
		ADD_CHECKPOINT(300,     "0a1c76baca667f7f87c04e86b0aad150277fc643a1d78763d95c0679493d4235");
		ADD_CHECKPOINT(450,     "f282ed97a947ab7102ab1ce5cf1b773b6173b1479461d4f3f925370a75922776");
		ADD_CHECKPOINT(600,     "dc7130ec8f96b8634dd3dd6c24662a728fe62d3d04f745d156320a0b2a0c5d6e");
		ADD_CHECKPOINT(750,     "ab4800f2fa32e3e10f7343651cd6541cdc2cbcfd79b17d67a66da55a02392ef4");
		ADD_CHECKPOINT(900,     "8d0e6d6fdc27d21c20b3140c5cfe6b5d59d65fa9f17d2930b99a433f160f9c6c");
		ADD_CHECKPOINT(1200,     "810eb6151a18b0e15c674e2932463694f0f4e3e208f82980856bd8b720f6936a");
		ADD_CHECKPOINT(1500,     "fbd3c8e6bf2b9d3736a43bf0e55267a52b64bb868a7932c5c4d8f9db68b4ebcb");
		ADD_CHECKPOINT(1800,     "ca680200c06f8ad4f29c5a275c6f01f6e99815a45953e41f9411398ec7721455");
		ADD_CHECKPOINT(2100,     "e3a683c8b94a9a9a843ba0e47724fc0845b5fa489213a9206b752c79cc05e7c5");
		ADD_CHECKPOINT(2500,     "cee897a08b05f332eb759800d5839f7029bc24298f936e4b3e26a22fe4334144");
		ADD_CHECKPOINT(3000,     "f245e68186cc366f2852b2506ef8090cf169fe4210c774b21a2896fd9bf66fd2");
		ADD_CHECKPOINT(3500,     "2382af55c01383c52497f30ab66e1102c426b07bef9c7f2d1853d4a992c75c2e");
		ADD_CHECKPOINT(4000,     "0fb9b6a263de6f06ede4e23bdbbb371ebe74b601f8d4682ee2d1407fc64f9742");
		ADD_CHECKPOINT(4500,     "08a8210c95b34772d516010d255578ef324ea099c9ef6a53f45a49119b8b80cb");
		ADD_CHECKPOINT(5000,     "cabe945ec7df9730639f6990cc908ae6939933a304ce6aaa0db3a0bdc3998821");
		ADD_CHECKPOINT(5500,     "06a62e9aeaa7d4540c4b39d082f5d7a181f395f6554c2baae8ca513e0e356cc6");
		ADD_CHECKPOINT(6000,     "33d5b9ce9eb332d9b9633302f488fe162d2f0464fceb2419a738a2028f0ba8ee");
		ADD_CHECKPOINT(6500,     "b197bbee7a880b9ddc3760646433b5ddd7d9baf34fe8dad64fa55541912534ec");
		ADD_CHECKPOINT(7000,     "6bcf592d69e3d2b1de5cda7e7bd8201086fb4ccbc63bc2d25e30614e0d433d0a");
		ADD_CHECKPOINT(7500,     "3f964e43830817104cecd85dd4952f458fe3d1bcc31a6366ae36a4634d1e0e95");
		ADD_CHECKPOINT(8000,     "fc1a70613aca87a2f5fcaeebeb6af7b95147524c81ee34a729dbf947a91ea921");
		ADD_CHECKPOINT(8500,     "99c80779191001af3a05ca84031890af71bc312e6798a9db9489a4b3607fed4e");
		ADD_CHECKPOINT(9000,     "34d681367dbcfb8eb3c9b47777d7db3c3b1976b092ec496f4a37b220a09baa87");
		ADD_CHECKPOINT(9500,     "80e4bcc413f196f92e51ba1ddfbf7323df817d9516f90a6e4c2a7de9f410211e");
		ADD_CHECKPOINT(10000,     "9640445ae7509b545b5131c6021cc9f46b57f1c8293d623e65a15c8a5dcdb079");
		

        break;
    }
    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = { "ck.saronite.info"
						     , "ck.saronite.io"
						     , "ck2.saronite.info"
						     , "ck2.saronite.io"
    };

    static const std::vector<std::string> testnet_dns_urls = { "tck.saronite.info"
							     , "tck2.saronite.info"
							     , "tck.saronite.io"
							     , "tck2.saronite.io"
    };

    static const std::vector<std::string> stagenet_dns_urls = { "sck.saronite.info"
                   , "sck2.saronite.info"
                   , "sck.saronite.io"
                   , "sck2.saronite.io"
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::parse_tpod_from_hex_string(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
