use prism_common::account::Account;

use crate::{PrismApi, RequestBuilder, builder::ModifyAccountRequestBuilder, noop::NoopPrismApi};

pub trait AccountExt {
    /// Creates a modification request builder for this account using the default `NoopPrismApi`.
    /// This is useful for local testing and validation without a real API connection.
    fn modify(&self) -> ModifyAccountRequestBuilder<'_, NoopPrismApi>;

    /// Creates a modification request builder for this account using the provided `PrismApi`
    /// implementation. This allows building and submitting transactions that modify the current
    /// account state through a specific API.
    fn modify_via_api<'a, P: PrismApi>(&self, prism: &'a P) -> ModifyAccountRequestBuilder<'a, P>;
}

impl AccountExt for Account {
    fn modify(&self) -> ModifyAccountRequestBuilder<'_, NoopPrismApi> {
        RequestBuilder::new().to_modify_account(self)
    }

    fn modify_via_api<'a, P: PrismApi>(&self, prism: &'a P) -> ModifyAccountRequestBuilder<'a, P> {
        RequestBuilder::new_with_prism(prism).to_modify_account(self)
    }
}
