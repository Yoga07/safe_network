// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use safe_network::types::register::{Entry, EntryHash};

use crate::url::{ContentType, Url, XorUrl};
use crate::{Error, Result, Safe};
use log::debug;
use safe_network::types::{DataAddress, RegisterAddress, Scope};
use std::collections::BTreeSet;
use xor_name::XorName;

impl Safe {
    /// Create a Register on the network
    pub async fn register_create(
        &self,
        name: Option<XorName>,
        type_tag: u64,
        private: bool,
    ) -> Result<XorUrl> {
        let xorname = self
            .safe_client
            .create_register(name, type_tag, None, private)
            .await?;

        let scope = if private {
            Scope::Private
        } else {
            Scope::Public
        };
        let xorurl =
            Url::encode_register(xorname, type_tag, scope, ContentType::Raw, self.xorurl_base)?;

        Ok(xorurl)
    }

    /// Read value from a Register on the network
    pub async fn register_read(&self, url: &str) -> Result<BTreeSet<(EntryHash, Entry)>> {
        debug!("Getting Public Register data from: {:?}", url);
        let safeurl = self.parse_and_resolve_url(url).await?;

        self.register_fetch_entries(&safeurl).await
    }

    /// Read value from a Register on the network by its hash
    pub async fn register_read_entry(&self, url: &str, hash: EntryHash) -> Result<Entry> {
        debug!("Getting Public Register data from: {:?}", url);
        let safeurl = self.parse_and_resolve_url(url).await?;

        self.register_fetch_entry(&safeurl, hash).await
    }

    /// Fetch a Register from a Url without performing any type of URL resolution
    /// Supports version hashes:
    /// e.g. safe://mysafeurl?v=ce56a3504c8f27bfeb13bdf9051c2e91409230ea
    pub(crate) async fn register_fetch_entries(
        &self,
        url: &Url,
    ) -> Result<BTreeSet<(EntryHash, Entry)>> {
        let result = match url.content_version() {
            Some(v) => {
                debug!("Take entry with version hash");
                let hash = v.entry_hash();
                self.register_fetch_entry(url, hash)
                    .await
                    .map(|entry| vec![(hash, entry)].into_iter().collect())
            }
            None => {
                debug!("No version so take latest entry");
                let address = self.get_register_address(url)?;
                self.safe_client.read_register(address).await
            }
        };

        match result {
            Ok(data) => {
                debug!("Register retrieved from {}...", url);
                Ok(data)
            }
            Err(Error::EmptyContent(_)) => Err(Error::EmptyContent(format!(
                "Register found at \"{}\" was empty",
                url
            ))),
            Err(Error::ContentNotFound(_)) => Err(Error::ContentNotFound(format!(
                "No Register found at \"{}\"",
                url
            ))),
            other_err => other_err,
        }
    }

    /// Fetch a Register from a Url without performing any type of URL resolution
    pub(crate) async fn register_fetch_entry(&self, url: &Url, hash: EntryHash) -> Result<Entry> {
        // TODO: allow to specify the hash with the Url as well: safeurl.content_hash(),
        // e.g. safe://mysafeurl#ce56a3504c8f27bfeb13bdf9051c2e91409230ea
        let address = self.get_register_address(url)?;
        self.safe_client.get_register_entry(address, hash).await
    }

    /// Write value to a Register on the network
    pub async fn register_write(
        &self,
        url: &str,
        entry: Entry,
        parents: BTreeSet<EntryHash>,
    ) -> Result<EntryHash> {
        /*
        let safeurl = Safe::parse_url(url)?;
        if safeurl.content_hash().is_some() {
            // TODO: perhaps we can allow this, and that's how an
            // application can specify the parent entry in the Register.
            return Err(Error::InvalidInput(format!(
                "The target URL cannot contain a content hash: {}",
                url
            )));
        };
        */

        let reg_url = self.parse_and_resolve_url(url).await?;
        let address = self.get_register_address(&reg_url)?;
        self.safe_client
            .write_to_register(address, entry, parents)
            .await
    }

    pub(crate) fn get_register_address(&self, url: &Url) -> Result<RegisterAddress> {
        let address = match url.address() {
            DataAddress::Register(reg_address) => reg_address,
            other => {
                return Err(Error::ContentError(format!(
                    "The url {} has an {:?} address.\
                    To fetch register entries, this url must refer to a register.",
                    url, other
                )))
            }
        };
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use crate::app::test_helpers::new_safe_instance;
    use anyhow::Result;

    #[tokio::test]
    async fn test_register_create() -> Result<()> {
        let safe = new_safe_instance().await?;

        let xorurl = safe.register_create(None, 25_000, false).await?;
        let xorurl_priv = safe.register_create(None, 25_000, true).await?;

        let received_data = safe.register_read(&xorurl).await?;
        let received_data_priv = safe.register_read(&xorurl_priv).await?;

        assert!(received_data.is_empty());
        assert!(received_data_priv.is_empty());

        let initial_data = "initial data bytes".as_bytes().to_vec();
        let hash = safe
            .register_write(&xorurl, initial_data.clone(), Default::default())
            .await?;
        let hash_priv = safe
            .register_write(&xorurl_priv, initial_data.clone(), Default::default())
            .await?;

        let received_entry = safe.register_read_entry(&xorurl, hash).await?;
        let received_entry_priv = safe.register_read_entry(&xorurl_priv, hash_priv).await?;

        assert_eq!(received_entry, initial_data.clone());
        assert_eq!(received_entry_priv, initial_data);

        Ok(())
    }
}
