use ecgfp5::scalar::Scalar;
use ecgfp5::curve::Point;

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let public_key = keygen([1, 2, 3, 4, 5]);
        println!("Public key: {:?}", public_key);
    }
}
