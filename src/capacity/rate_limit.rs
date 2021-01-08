// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{capacity::Capacity, Network, Result};
use log::info;
use sn_data_types::{Money, PublicKey};

const MAX_CHUNK_SIZE: u64 = 1_000_000;
const MAX_SUPPLY: u64 = u32::MAX as u64 * 1_000_000_000_u64;
const MAX_NETWORK_STORAGE_RATIO: f64 = 0.5;

/// Calculation of rate limit for writes.
pub struct RateLimit {
    network: Network,
    capacity: Capacity,
}

impl RateLimit {
    /// Ctor
    pub fn new(network: Network, capacity: Capacity) -> RateLimit {
        Self { network, capacity }
    }

    /// Calculates the rate limit of write operations,
    /// as a cost to be paid for a certain number of bytes.
    pub async fn from(&self, bytes: u64) -> Money {
        let prefix = self.network.our_prefix().await;
        let prefix_len = prefix.bit_count();

        let full_nodes = self.capacity.full_nodes();
        let all_nodes = self.network.our_adults().await.len() as u8;

        RateLimit::rate_limit(
            bytes,
            full_nodes,
            all_nodes,
            prefix_len,
        )
    }

    fn rate_limit(
        bytes: u64,
        full_nodes: u8,
        all_nodes: u8,
        prefix_len: usize,
    ) -> Money {
        let available_nodes = (all_nodes - full_nodes) as f64;
        let supply_demand_factor = 0.001
            + (1_f64 / available_nodes).powf(8_f64)
            + (full_nodes as f64 / all_nodes as f64).powf(88_f64);
        let data_size_factor = (bytes as f64 / MAX_CHUNK_SIZE as f64).powf(2_f64)
            + (bytes as f64 / MAX_CHUNK_SIZE as f64);
        let steepness_reductor = prefix_len as f64 + 1_f64;
        let section_supply_share = RateLimit::max_section_coins(prefix_len);
        let token_source = steepness_reductor * section_supply_share.powf(0.5_f64);
        let rate_limit = (token_source * data_size_factor * supply_demand_factor).round() as u64;
        Money::from_nano(rate_limit)
    }

    fn max_section_coins(prefix_len: usize) -> f64 {
        MAX_SUPPLY as f64 / 2_f64.powf(prefix_len as f64)
    }

    ///
    pub fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<()> {
        self.capacity.increase_full_node_count(node_id)
    }

    ///
    pub async fn check_network_storage(&self) -> bool {
        info!("Checking network storage");
        let all_nodes = self.network.our_adults().await.len() as f64;
        let full_nodes = self.capacity.full_nodes() as f64;
        let usage_ratio = full_nodes / all_nodes;
        info!("Total number of adult nodes: {:?}", all_nodes);
        info!("Number of Full adult nodes: {:?}", full_nodes);
        info!("Section storage usage ratio: {:?}", usage_ratio);
        usage_ratio > MAX_NETWORK_STORAGE_RATIO
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn calculates_rate_limit() -> Result<()> {
        let bytes = 1_000;
        let prefix_len = 0;
        let all_nodes = 8;
        let full_nodes = 7;
        let rate_limit = RateLimit::rate_limit(
            bytes,
            full_nodes,
            all_nodes,
            prefix_len,
        )
        .as_nano();
        assert_eq!(rate_limit, 2076594);
        Ok(())
    }

    #[test]
    fn calculates_max_section_coins() -> Result<()> {
        let max_supply_f64 = MAX_SUPPLY as f64;
        // prefix zero is one section so is responsible for all coins
        let first_section_coins = RateLimit::max_section_coins(0);
        assert_eq!(max_supply_f64, first_section_coins);
        // first split leads to each section having half the coins
        let first_split_coins = RateLimit::max_section_coins(1);
        assert_eq!(max_supply_f64 / 2.0, first_split_coins);
        // last split leads to some coins remaining in section
        let last_split_coins = RateLimit::max_section_coins(256);
        assert!(last_split_coins > 0.0);
        Ok(())
    }

    #[test]
    #[ignore] // these tests fail with the current implementation
    fn rate_limit_common_sense() -> Result<()> {
        // setup
        let one_mb_bytes = 1024 * 1024;
        let prefix_len = 0;
        let all_nodes = 8;
        let full_nodes = 7;
        let standard_rl = RateLimit::rate_limit(
            one_mb_bytes,
            full_nodes,
            all_nodes,
            prefix_len,
        )
        .as_nano();
        // Test various different comparisons of the storecost.
        // These tests are of the type 'all things being equal, then ...'
        {
            // smaller chunks cost less
            let one_mb_less_one_byte = one_mb_bytes - 1;
            let small = RateLimit::rate_limit(
                one_mb_less_one_byte,
                full_nodes,
                all_nodes,
                prefix_len,
            )
            .as_nano();
            assert!(small <= standard_rl, "small chunks don't cost less, expect {} <= {}", small, standard_rl);
        };
        {
            // large network is cheaper to store than smaller network
            let big_prefix_len = prefix_len + 1;
            let big = RateLimit::rate_limit(
                one_mb_bytes,
                full_nodes,
                all_nodes,
                big_prefix_len,
            )
            .as_nano();
            assert!(big <= standard_rl, "larger network is not cheaper, expect {} <= {}", big, standard_rl);
        };
        {
            // less full section is cheaper than more full section
            let less_full_nodes = full_nodes - 1;
            let empty = RateLimit::rate_limit(
                one_mb_bytes,
                less_full_nodes,
                all_nodes,
                prefix_len,
            )
            .as_nano();
            assert!(empty <= standard_rl, "less full section is not cheaper, expect {} <= {}", empty, standard_rl);
        };
        {
            // one big chunk is cheaper than the same bytes in many tiny chunks
            let one_kb_bytes = 1024;
            let reduced = RateLimit::rate_limit(
                one_kb_bytes,
                full_nodes,
                all_nodes,
                prefix_len,
            )
            .as_nano();
            let combined = 1024 * reduced;
            assert!(standard_rl <= combined, "one big chunk is not cheaper than many small ones, expect {} <= {}", standard_rl, combined);
        };
        {
            // storage is never free even for most optimistic circumstances
            let one_byte = 1;
            let half_full_nodes = 99;
            let big_section_node_count = 199;
            let big_prefix_len = 256;
            let endcost = RateLimit::rate_limit(
                one_byte,
                half_full_nodes,
                big_section_node_count,
                big_prefix_len,
            )
            .as_nano();
            assert!(endcost > 0, "cost is not always greater than zero: cost is {}", endcost);
        };
        {
            // the first chunk is a reasonable cost
            let max_initial_cost = 1_000 * 1_000_000_000; // 1000 tokens
            let zero_full_nodes = 0;
            let minimum_section_nodes = 5;
            let first_section_prefix = 0;
            let startcost = RateLimit::rate_limit(
                one_mb_bytes,
                zero_full_nodes,
                minimum_section_nodes,
                first_section_prefix,
            )
            .as_nano();
            assert!(startcost < max_initial_cost, "initial cost {} is above {}", startcost, max_initial_cost);
        };
        Ok(())
    }
}
