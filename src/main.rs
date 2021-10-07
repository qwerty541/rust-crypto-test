#![allow(non_fmt_panics)]

use crypto::aessafe;
use crypto::blockmodes;
use crypto::buffer;
use crypto::symmetriccipher;
use rand::rngs::OsRng;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;
use std::cmp::{self, Ord};
use std::convert::From;
use std::io;

pub type AesCbcEncryptor = blockmodes::CbcEncryptor<
    aessafe::AesSafe256Encryptor,
    blockmodes::EncPadding<blockmodes::NoPadding>,
>;

pub type AesCbcDecryptor = blockmodes::CbcDecryptor<
    aessafe::AesSafe256Decryptor,
    blockmodes::DecPadding<blockmodes::NoPadding>,
>;

const EOF: bool = true;
const EXPECTED_AES_BLOCK_LENGTH: usize = 16;
const MINIMUN_ENCRYPTED_PACKAGE_LENGTH: usize = 64;
const ENCRYPTED_PACKAGE_META_LENGTH: usize = 2;

pub fn decrypt_buf<'a>(
    decryptor: &mut AesCbcDecryptor,
    decryptor_block_length: usize,
    buf: &'a mut [u8],
) -> io::Result<Vec<u8>> {
    if buf.len() < MINIMUN_ENCRYPTED_PACKAGE_LENGTH {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Read buffer data length less that {}, its length - {}",
                MINIMUN_ENCRYPTED_PACKAGE_LENGTH,
                buf.len()
            ),
        ));
    }

    if buf.len() % decryptor_block_length != 0_usize {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Read buffers data length not divisible by {} without a remainder, its length - {}",
                decryptor_block_length,
                buf.len()
            ),
        ));
    }

    dbg!(&buf);

    let mut decrypted_buf: Vec<u8> = Vec::new();
    let mut read_buffer = buffer::RefReadBuffer::new(buf);
    let mut write_buffer_inner = vec![0_u8; buf.len()];
    let mut write_buffer = buffer::RefWriteBuffer::new(write_buffer_inner.as_mut_slice());

    'decryption: loop {
        let result = <AesCbcDecryptor as symmetriccipher::Decryptor>::decrypt(
            decryptor,
            &mut read_buffer,
            &mut write_buffer,
            EOF,
        )
        .map_err(|symmetriccipher_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Decryption failed because {:?}", symmetriccipher_error),
            )
        })?;

        decrypted_buf.extend(
            <buffer::RefReadBuffer<'_> as buffer::ReadBuffer>::take_remaining(
                &mut <buffer::RefWriteBuffer<'_> as buffer::WriteBuffer>::take_read_buffer(
                    &mut write_buffer,
                ),
            )
            .iter()
            .copied(),
        );

        match result {
            buffer::BufferResult::BufferUnderflow => break 'decryption,
            buffer::BufferResult::BufferOverflow => continue 'decryption,
        }
    }

    dbg!(&decrypted_buf);

    let garbage_length = match decrypted_buf.split_last() {
        Some((last, _)) => *last,
        None => {
            return io::Result::Err(io::Error::new(
                io::ErrorKind::InvalidData,
                String::from("Empty decryption result"),
            ))
        }
    };
    let payload_length = decrypted_buf.len() - garbage_length as usize;
    let payload = decrypted_buf.split_off(payload_length);
    let garbage_bytes = decrypted_buf;
    let input_lrc = match garbage_bytes.first() {
        Some(input_lrc) => *input_lrc,
        None => {
            return io::Result::Err(io::Error::new(
                io::ErrorKind::InvalidData,
                String::from("Failed to extract LRC from garbage bytes"),
            ))
        }
    };
    let lrc = calculate_lrc(payload.as_slice());

    if lrc != input_lrc {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "LRC check failed: calculated: {}, received: {}",
                lrc, input_lrc
            ),
        ));
    }

    Ok(payload)
}

pub fn encrypt_buf<'a>(
    encryptor: &mut AesCbcEncryptor,
    encryptor_block_length: usize,
    buf: &'a [u8],
) -> io::Result<Vec<u8>> {
    if buf.is_empty() {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            String::from("Provided write buffer has no data"),
        ));
    }

    let mut bytes_that_will_be_encrypted: Vec<u8> = Vec::new();
    bytes_that_will_be_encrypted.extend_from_slice(buf);

    let lrc = calculate_lrc(buf);

    match buf
        .len()
        .cmp(&(MINIMUN_ENCRYPTED_PACKAGE_LENGTH - ENCRYPTED_PACKAGE_META_LENGTH))
    {
        cmp::Ordering::Equal => {
            bytes_that_will_be_encrypted.push(lrc);
            bytes_that_will_be_encrypted.push(ENCRYPTED_PACKAGE_META_LENGTH as u8);
        }
        cmp::Ordering::Greater => {
            let mut rng = thread_rng();
            let random_bytes_legth =
                (buf.len() + ENCRYPTED_PACKAGE_META_LENGTH) % EXPECTED_AES_BLOCK_LENGTH;

            bytes_that_will_be_encrypted.push(lrc);

            for _ in 0_usize..random_bytes_legth {
                bytes_that_will_be_encrypted.push(rng.gen());
            }

            bytes_that_will_be_encrypted
                .push((random_bytes_legth + ENCRYPTED_PACKAGE_META_LENGTH) as u8)
        }
        cmp::Ordering::Less => {
            let mut rng = thread_rng();
            let random_bytes_legth =
                (MINIMUN_ENCRYPTED_PACKAGE_LENGTH - ENCRYPTED_PACKAGE_META_LENGTH) - buf.len();

            bytes_that_will_be_encrypted.push(lrc);

            for _ in 0_usize..random_bytes_legth {
                bytes_that_will_be_encrypted.push(rng.gen());
            }

            bytes_that_will_be_encrypted
                .push((random_bytes_legth + ENCRYPTED_PACKAGE_META_LENGTH) as u8)
        }
    }

    if bytes_that_will_be_encrypted.len() < MINIMUN_ENCRYPTED_PACKAGE_LENGTH {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Length of buffer with bytes that will be encrypted less than {}",
                MINIMUN_ENCRYPTED_PACKAGE_LENGTH
            ),
        ));
    }

    if (bytes_that_will_be_encrypted.len() % encryptor_block_length) != 0_usize {
        return io::Result::Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Length of buffer with bytes that will be enrypted is not divisible by {} without remainder",
                encryptor_block_length
            ),
        ));
    }

    dbg!(&bytes_that_will_be_encrypted);

    let mut encrypted_buf: Vec<u8> = Vec::new();
    let mut read_buffer = buffer::RefReadBuffer::new(bytes_that_will_be_encrypted.as_slice());
    let mut write_buffer_inner = vec![0_u8; bytes_that_will_be_encrypted.len()];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut write_buffer_inner);

    'encryption: loop {
        let result = <AesCbcEncryptor as symmetriccipher::Encryptor>::encrypt(
            encryptor,
            &mut read_buffer,
            &mut write_buffer,
            EOF,
        )
        .map_err(|symmetriccipher_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Encryption failed because {:?}", symmetriccipher_error),
            )
        })?;

        encrypted_buf.extend(
            <buffer::RefReadBuffer<'_> as buffer::ReadBuffer>::take_remaining(
                &mut <buffer::RefWriteBuffer<'_> as buffer::WriteBuffer>::take_read_buffer(
                    &mut write_buffer,
                ),
            )
            .iter()
            .copied(),
        );

        match result {
            buffer::BufferResult::BufferUnderflow => break 'encryption,
            buffer::BufferResult::BufferOverflow => continue 'encryption,
        }
    }

    dbg!(&encrypted_buf);

    assert!(
        encrypted_buf.len() >= MINIMUN_ENCRYPTED_PACKAGE_LENGTH,
        format!(
            "Encryption algorithm failed: encrypted buffer length less than {}",
            MINIMUN_ENCRYPTED_PACKAGE_LENGTH
        )
    );

    assert!(
        encrypted_buf.len() % encryptor_block_length == 0_usize,
        format!(
            "Encryption algorithm failed: encrypted buffer is not divisible by {} without remained",
            encryptor_block_length
        )
    );

    Ok(encrypted_buf)
}

pub fn calculate_lrc(buf: &'_ [u8]) -> u8 {
    let mut counter = 0_u8;
    for byte in buf {
        counter = counter.wrapping_add(*byte);
    }
    counter
}

fn main() {
    #[rustfmt::skip]
    let shared_secret_key: Vec<u8> = vec![
        0x0F, 0x01, 0x09, 0x07, 0x0A, 0x02, 0x02, 0x04,
        0x0F, 0x0D, 0x0F, 0x04, 0x01, 0x07, 0x00, 0x01,
        0x0F, 0x0E, 0x0E, 0x0B, 0x08, 0x0B, 0x00, 0x0A,
        0x0F, 0x02, 0x02, 0x01, 0x03, 0x0B, 0x06, 0x03
    ];
    let mut encryption_iv = [0_u8; 16];
    let mut decryption_iv = [0_u8; 16];
    let mut os_rng = OsRng::default();

    os_rng.fill_bytes(&mut encryption_iv);
    os_rng.fill_bytes(&mut decryption_iv);

    let aes_encryptor = aessafe::AesSafe256Encryptor::new(shared_secret_key.as_slice());
    let encryptor_block_length =
        <aessafe::AesSafe256Encryptor as symmetriccipher::BlockEncryptor>::block_size(
            &aes_encryptor,
        );

    let aes_decryptor = aessafe::AesSafe256Decryptor::new(shared_secret_key.as_slice());
    let decryptor_block_length =
        <aessafe::AesSafe256Decryptor as symmetriccipher::BlockDecryptor>::block_size(
            &aes_decryptor,
        );

    let mut encryptor =
        blockmodes::CbcEncryptor::new(aes_encryptor, blockmodes::NoPadding, encryption_iv.to_vec());
    let mut decryptor =
        blockmodes::CbcDecryptor::new(aes_decryptor, blockmodes::NoPadding, decryption_iv.to_vec());

    #[rustfmt::skip]
    let data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    ];

    let mut encrypted_data =
        encrypt_buf(&mut encryptor, encryptor_block_length, data.as_slice()).unwrap();
    let decrypted_data = decrypt_buf(
        &mut decryptor,
        decryptor_block_length,
        encrypted_data.as_mut_slice(),
    )
    .unwrap();

    assert_eq!(data.as_slice(), decrypted_data.as_slice());
}
