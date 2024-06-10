use ecgfp5::scalar::Scalar;
use ecgfp5::curve::Point;

#[derive(Clone, Debug)]
pub struct CardCipher {
    ca: Point,
    cb: Point
}

#[derive(Debug)]
pub struct Card(Point);

pub fn keygen(secret_key: [u64; 5]) -> Point {
    let g = Point::GENERATOR;
    let scalar = Scalar::from_val(secret_key);
    let public_key = g * scalar;
    public_key
}

pub fn mask(pub_agg: Point, m: Point, r: Scalar) -> CardCipher {
    let g = Point::GENERATOR;
    let ca = r * g;
    let cb = m + (r * pub_agg);
    CardCipher { ca, cb }
}

pub fn remask(pub_agg: Point, cipher: CardCipher, r: Scalar) -> CardCipher {
    let g = Point::GENERATOR;
    let new_ca = cipher.ca + (r * g);
    let new_cb = cipher.cb + (r * pub_agg);
    CardCipher { ca: new_ca, cb: new_cb }
}

pub fn inter_unmask(pub_agg: Point, cipher: CardCipher, r: Scalar) -> CardCipher {
    let g = Point::GENERATOR;
    let new_ca = cipher.ca - (r * g);
    let new_cb = cipher.cb - (r * pub_agg);
    CardCipher { ca: new_ca, cb: new_cb }
}

pub fn final_unmask(pub_agg: Point, cipher: CardCipher, r: Scalar) -> Card {
    let m = cipher.cb - (r * pub_agg);
    Card(m)
}

fn gen_card() -> Point {
    let g = Point::GENERATOR;
    let rndm: Scalar = Scalar::from_val([1,1,1,1,1]);
    let card = g * rndm;
    card 
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let secret_key: [u64; 5] = [1, 2, 3, 4, 5];
        let public_key = keygen(secret_key);
        let card = gen_card();
        println!("Plaintext card: {:?}", card);
        let masking_factor_1: Scalar = Scalar::from_val([2u64, 2u64, 2u64, 2u64 ,2u64]);
        let masking_factor_2: Scalar = Scalar::from_val([3u64, 3u64, 3u64, 3u64 ,3u64]);
        let mask_card = mask(public_key, card, masking_factor_1);
        let remask_card = remask(public_key, mask_card, masking_factor_2);
        let inter_unmask_card = inter_unmask(public_key, remask_card, masking_factor_2);
        let final_unmask_card = final_unmask(public_key, inter_unmask_card, masking_factor_1);
        println!("Card: {:?}", card);
    }
}
