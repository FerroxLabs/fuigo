//! P121 (K6): a helper client is rebuilt exactly when the model or the catalog it was resolved
//! against has changed, and not on every request.
use super::helper_epoch::{EpochCache, HelperEpoch};
use std::cell::Cell;

#[tokio::test]
async fn a_helper_is_rebuilt_only_when_the_epoch_moves() {
    let built = Cell::new(0u32);
    let mut cache = EpochCache::new();
    macro_rules! get {
        ($epoch:expr) => {
            *cache
                .get_or_rebuild($epoch, || async {
                    built.set(built.get() + 1);
                    built.get()
                })
                .await
        };
    }
    let start = HelperEpoch { model_switch: 0, catalog_reload: 0, session_switches: 0 };
    assert_eq!(get!(start), 1, "built on first use");
    assert_eq!(get!(start), 1, "kept while nothing moved");
    let switched = HelperEpoch { model_switch: 1, ..start };
    assert_eq!(get!(switched), 2, "rebuilt after a model switch");
    assert_eq!(get!(switched), 2);
    let reloaded = HelperEpoch { catalog_reload: 1, ..switched };
    assert_eq!(get!(reloaded), 3, "rebuilt after a catalog reload");
    assert_eq!(get!(reloaded), 3);
    assert_eq!(built.get(), 3);
}
