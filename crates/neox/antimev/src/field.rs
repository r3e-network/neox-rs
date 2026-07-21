//! Safe wrappers around the BLST scalar-field operations shared by DKG and TPKE.

#[cfg(feature = "std")]
use blst::blst_fr_add;
use blst::{blst_fr, blst_fr_from_uint64, blst_fr_mul, blst_fr_sub};

pub(super) fn from_u64(value: u64) -> blst_fr {
    let limbs = [value, 0, 0, 0];
    let mut result = blst_fr::default();
    // SAFETY: BLST expects four little-endian u64 limbs and `limbs` has exactly that shape.
    unsafe { blst_fr_from_uint64(&raw mut result, limbs.as_ptr()) };
    result
}

#[cfg(feature = "std")]
pub(super) fn add(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_add(&raw mut result, left, right) };
    result
}

pub(super) fn multiply(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_mul(&raw mut result, left, right) };
    result
}

pub(super) fn subtract(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_sub(&raw mut result, left, right) };
    result
}
