use sodalite::*;

use rustler::types::{Binary, OwnedBinary};
use rustler::Error::BadArg;
use rustler::{Encoder, Env, NifResult, Term};

mod atoms {
    rustler::atoms! {
        ok,
        t = "true",
        f = "false",
    }
}

rustler::init!("rsalt", [nif_secretbox, nif_secretbox_open]);

const SECRETBOX_ZEROBYTES: usize = 32;
const SECRETBOX_BOXZEROBYTES: usize = 16;

fn with_zero(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.resize(len, 0);
    v
}

fn with_prefix(buf: &[u8], prefix_len: usize) -> Vec<u8> {
    let mut v = with_zero(buf.len() + prefix_len);
    (&mut v[prefix_len..]).copy_from_slice(&buf);
    v
}

fn to_fixed_buf<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    (&mut out[..]).copy_from_slice(buf);
    out
}

#[rustler::nif]
fn nif_secretbox<'a>(
    env: Env<'a>,
    data: Term<'a>,
    nonce: Term<'a>,
    secret_key: Term<'a>,
) -> NifResult<Term<'a>> {
    let data = Binary::from_term(data)?;
    let nonce = Binary::from_term(nonce)?;
    let secret_key = Binary::from_term(secret_key)?;

    if nonce.len() != SECRETBOX_NONCE_LEN || secret_key.len() != SECRETBOX_KEY_LEN {
        return Err(BadArg);
    }

    let data_buf = with_prefix(data.as_slice(), SECRETBOX_ZEROBYTES);
    let nonce = to_fixed_buf::<SECRETBOX_NONCE_LEN>(nonce.as_slice());
    let secret_key = to_fixed_buf::<SECRETBOX_KEY_LEN>(secret_key.as_slice());
    let mut out_buf = with_zero(data_buf.len());

    if let Err(_) = sodalite::secretbox(&mut out_buf, &data_buf, &nonce, &secret_key) {
        return Err(BadArg);
    }

    let mut bin = OwnedBinary::new(out_buf.len() - SECRETBOX_BOXZEROBYTES).ok_or(BadArg)?;
    (&mut bin).copy_from_slice(&out_buf[SECRETBOX_BOXZEROBYTES..]);

    Ok((atoms::ok(), Binary::from_owned(bin, env).to_term(env)).encode(env))
}

#[rustler::nif]
fn nif_secretbox_open<'a>(
    env: Env<'a>,
    data: Term<'a>,
    nonce: Term<'a>,
    secret_key: Term<'a>,
) -> NifResult<Term<'a>> {
    let data = Binary::from_term(data)?;
    let nonce = Binary::from_term(nonce)?;
    let secret_key = Binary::from_term(secret_key)?;

    if nonce.len() != SECRETBOX_NONCE_LEN || secret_key.len() != SECRETBOX_KEY_LEN {
        return Err(BadArg);
    }

    let data_buf = with_prefix(data.as_slice(), SECRETBOX_BOXZEROBYTES);
    let nonce = to_fixed_buf::<SECRETBOX_NONCE_LEN>(nonce.as_slice());
    let secret_key = to_fixed_buf::<SECRETBOX_KEY_LEN>(secret_key.as_slice());
    let mut out_buf = with_zero(data_buf.len());

    if let Err(_) = sodalite::secretbox_open(&mut out_buf, &data_buf, &nonce, &secret_key) {
        return Err(BadArg);
    }

    let mut bin = OwnedBinary::new(out_buf.len() - SECRETBOX_ZEROBYTES).ok_or(BadArg)?;
    (&mut bin).copy_from_slice(&out_buf[SECRETBOX_ZEROBYTES..]);

    Ok((atoms::ok(), Binary::from_owned(bin, env).to_term(env)).encode(env))
}
