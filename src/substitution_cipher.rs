extern crate rand;

use rand::{thread_rng, Rng};
use regex::Regex;
use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
};

const ALPHABET: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

// Given a ciphertext and a key, this function returns the plaintext.
fn build_plaintext(ciphertext: &str, key: &[char; 26]) -> String {
    let mut plaintext = String::new();
    let mut key_map = HashMap::new();

    for i in 0..26 {
        key_map.insert(key[i], ALPHABET[i]);
    }

    for (i, c) in ciphertext.chars().enumerate() {
        if c != ' ' {
            plaintext.push(key_map[&c]);
        } else {
            plaintext.push(' ');
        }
    }
    plaintext
}

// Given a plaintext, we calculate the score with respect to the frequency table of ngrams.
fn score(plaintext: &String, ngram: usize, ngram_log_p_table: &HashMap<String, f64>) -> f64 {
    let mut score = 0.0;
    for i in 0..plaintext.len() - ngram {
        let ngram = &plaintext[i..i + ngram];
        if ngram_log_p_table.contains_key(ngram) {
            score += ngram_log_p_table[ngram];
        } else {
            score -= 10.0;
        }
    }
    return score;
}

fn generate_ngram_log_p_table(ngram: usize) -> HashMap<String, f64> {
    let filter_alphanum_re = Regex::new(r"[^A-z0-9 ]").unwrap();
    let english_text_sample = include_str!("../war_and_peace.txt");

    // Deletes all characters which are not letters, numbers or space.
    let english_text_stripped = filter_alphanum_re
        .replace_all(english_text_sample, "")
        .to_uppercase();

    // Generate n-gram frequency table and compute logarithmic probability table
    let mut ngram_freq_table = HashMap::<String, u64>::new();
    let mut total_ngrams: u64 = 0;

    for i in 0..english_text_stripped.len() - ngram {
        let curr_ngram = &english_text_stripped[i..i + ngram];
        if curr_ngram.contains(" ") {
            continue;
        }
        if ngram_freq_table.contains_key(&curr_ngram.to_string()) {
            ngram_freq_table.insert(curr_ngram.to_string(), ngram_freq_table[curr_ngram] + 1);
        } else {
            ngram_freq_table.insert(curr_ngram.to_string(), 1);
        }
        total_ngrams += 1;
    }

    let mut ngram_log_p_table = HashMap::<String, f64>::new();
    for key in ngram_freq_table.keys() {
        ngram_log_p_table.insert(
            key.to_string(),
            (ngram_freq_table[key] as f64 / total_ngrams as f64).log10(),
        );
    }
    ngram_log_p_table
}

// Returns the decrypted message together with the key.
fn decrypt(cryptogram: &str, ngram: usize) {
    let mut ngram_log_p_table = generate_ngram_log_p_table(ngram);
    let mut e = 0;
    loop {
        let mut hypothesis_key = ALPHABET;
        let mut iterations: u32 = 0;
        let mut plaintext = build_plaintext(cryptogram, &hypothesis_key);
        let mut result = score(&plaintext, ngram, &ngram_log_p_table);
        let mut rng = thread_rng();

        while iterations < 100000 {
            let mut candidate_key = hypothesis_key;
            candidate_key.swap(rng.gen_range(0..26), rng.gen_range(0..26));
            let candidate_plaintext = build_plaintext(cryptogram, &candidate_key);
            let candidate_result = score(&candidate_plaintext, ngram, &ngram_log_p_table);
            if candidate_result > result {
                result = candidate_result;
                hypothesis_key = candidate_key;
                plaintext = candidate_plaintext;
                iterations = 0;
            } else {
                iterations += 1;
            }
        }
        if e == 10 {
            break;
        }
        e += 1;
        println!("{}", plaintext);
    }
    //(plaintext, hypothesis_key)
}

fn build_cryptogram(plaintext: &str, key: &[char; 26]) -> String {
    let mut alphabet_index = HashMap::new();
    let mut i: usize = 0;
    for c in ALPHABET {
        alphabet_index.insert(c, i);
        i += 1;
    }

    let mut cryptogram = String::new();
    for c in plaintext.chars() {
        //println!("alphabet_index of {} is {}.", c, alphabet_index[&c]);
        if c != ' ' {
            cryptogram.push(key[alphabet_index[&c]]);
        } else {
            cryptogram.push(' ');
        }
    }
    cryptogram
}
#[test]
fn test_build_plaintext() {
    let ciphertext = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
    let mut key: [char; 26] = ALPHABET;
    key.reverse();
    assert_eq!(
        build_plaintext(ciphertext, &key),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    );
}

#[test]
fn test_build_cryptogram() {
    let plaintext: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut key: [char; 26] = ALPHABET;
    key.reverse();
    assert_eq!(
        build_cryptogram(plaintext, &key),
        "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    )
}

#[test]
fn test_decrypt() {
    let plaintext = "THIS IS THE MOST IMPORTANT TESTING METHOD IN THIS PROGRAM MAYBE IT WILL MAKE MORE SENSE IF I ADD MORE WORDS TO THIS THING";
    let key = [
        'Q', 'A', 'Z', 'W', 'S', 'X', 'E', 'D', 'C', 'R', 'F', 'V', 'T', 'G', 'B', 'Y', 'H', 'N',
        'U', 'J', 'M', 'I', 'K', 'O', 'L', 'P',
    ];
    let ciphertext = build_cryptogram(plaintext, &key);

    //human intervention needed here, by reading the outputs from this test the message can be decrypted
    decrypt(ciphertext.as_str(), 2);
    decrypt(ciphertext.as_str(), 3);
    decrypt(ciphertext.as_str(), 4);

    //let (a, b) = decrypt(ciphertext.as_str(), 3);
    //println!("{}", a);
}


// This is an example from the book Understanding Cryptograpy.
#[test]
fn book_test_decrypt() {
    let ciphertext = "LRVMNIR BPR SUMVBWVR JX BPR LMIWV YJERYRKBI JX QMBM WI BPR XJVNI MKD YMIBRUT JX IRHX WI BPR RIIRKVR JX YMBINLMTMIPW UTN QMUMBR DJ W IPMHH BUT BJ RHNVWDMBR BPRYJERYRKBI JX BPR QMBM MVVJUDWKO BJ YT WKBRUSURBMBWJKLMIRD JK XJUBT TRMUI JX IBNDTWB WI KJB MK RMIT BMIQ BJ RASHMWK RMVP YJERYRKB MKD WBIIWOKWXWVMKVR MKD IJYR YNIB URYMWK NKRASHMWKRD BJ OWER MVJYSHRBR RASHMKMBWJK JKR CJNHD PMER BJ LR FNMHWXWRD MKDWKISWURD BJ INVP MK RABRKB BPMB PR VJNHD URMVP BPR IBMBRJX RKHWOPBRKRD YWKD VMSMLHR JX URVJOKWGWKO IJNKDHRIIIJNKD MKD IPMSRHRII IPMSR W DJ KJB DRRY YTIRHX BPR XWKMHMNBPJUWBT LNB YT RASRUWRKVR CWBP QMBM PMI HRXB KJ DJNLBBPMB BPR XJHHJCWKO WI BPR SUJSRU MSSHWVMBWJK MKDWKBRUSURBMBWJK W JXXRU YT BPRJUWRI WK BPR PJSR BPMB BPRRIIRKVR JX JQWKMCMK QMUMBR CWHH URYMWK WKBMVB";
    decrypt(ciphertext, 2);
}
