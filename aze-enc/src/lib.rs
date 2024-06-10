use ecgfp5::scalar::Scalar;
use ecgfp5::field::GFp5;
use ecgfp5::curve::{Point};
use std::assert_eq;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Clone, Debug)]
pub struct CardCipher {
    ca: Point,
    cb: Point
}

#[derive(Debug)]
pub struct Card(Point);

const RNDM_PT: GFp5 = GFp5::from_u64_reduce(12539254003028696409, 15524144070600887654, 15092036948424041984, 11398871370327264211, 10958391180505708567);

pub fn keygen(secret_key: u32) -> Point {
    let (g, c) = Point::decode(RNDM_PT);
    // println!("Is valid {:?}", Point::validate(RNDM_PT));
    g.mdouble(secret_key) // g*2^secret_key
}

pub fn mask(pub_agg: Point, m: Point, r: u32) -> CardCipher {
    let ca: Point = pub_agg.mdouble(r); // pub_agg * 2^r
    let cb: Point = m + pub_agg.mdouble(r);
    CardCipher { ca, cb }
}

pub fn remask(pub_agg: Point, cipher: CardCipher, r: u32) -> CardCipher {
    let (g, c) = Point::decode(RNDM_PT);
    let new_ca = cipher.ca + g.mdouble(r);
    let new_cb = cipher.cb + pub_agg.mdouble(r);
    CardCipher { ca: new_ca, cb: new_cb }
}

pub fn inter_unmask(pub_agg: Point, cipher: CardCipher, r: u32) -> CardCipher {
    let (g, _) =  Point::decode(RNDM_PT);
    let new_ca = cipher.ca - g.mdouble(r);
    let new_cb = cipher.cb - pub_agg.mdouble(r);
    CardCipher { ca: new_ca, cb: new_cb }
}

pub fn final_unmask(pub_agg: Point, cipher: CardCipher, r: u32) -> Card {
    let m = cipher.cb - (pub_agg.mdouble(r));
    Card(m)
}

fn gen_card() -> Point {
    let (g, c) = Point::decode(RNDM_PT);
    g.mdouble(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let secret_key: u32 = 2;
        let public_key = keygen(secret_key);
        // println!("Public key: {:?}", public_key);
        let card = gen_card();
        println!("Plaintext card: {:?}", card);
        let masking_factor_1: u32 = 5;
        let masking_factor_2: u32 = 6;
        let mask_card = mask(public_key, card, masking_factor_1);
        // println!("Masked card: {:?}", mask_card);
        let remask_card = remask(public_key, mask_card.clone(), masking_factor_2);
        let inter_unmask_card = inter_unmask(public_key, remask_card, masking_factor_2);
        let final_unmask_card = final_unmask(public_key, inter_unmask_card, masking_factor_1);
        println!("Final unmasked card: {:?}", final_unmask_card.0);
        println!("Card: {:?}", final_unmask_card.0.equals(card));
    }
}
