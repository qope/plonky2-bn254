use ark_bn254::G1Affine;
use ark_std::UniformRand;
use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use rand::SeedableRng;

use crate::fields::{fq_target::FqTarget, fr_target::FrTarget};

#[derive(Clone, Debug)]
pub struct G1Target<F: RichField + Extendable<D>, const D: usize> {
    pub x: FqTarget<F, D>,
    pub y: FqTarget<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> G1Target<F, D> {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = FqTarget::empty(builder);
        let y = FqTarget::empty(builder);
        G1Target { x, y }
    }

    pub fn construct(x: FqTarget<F, D>, y: FqTarget<F, D>) -> Self {
        G1Target { x, y }
    }

    pub fn constant(builder: &mut CircuitBuilder<F, D>, a: G1Affine) -> Self {
        let x = a.x;
        let y = a.y;

        let x_target = FqTarget::constant(builder, x);
        let y_target = FqTarget::constant(builder, y);

        G1Target {
            x: x_target,
            y: y_target,
        }
    }

    pub fn connect(builder: &mut CircuitBuilder<F, D>, lhs: &Self, rhs: &Self) {
        FqTarget::connect(builder, &lhs.x, &rhs.x);
        FqTarget::connect(builder, &lhs.y, &rhs.y);
    }

    pub fn neg(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = self.x.clone();
        let y = self.y.neg(builder);
        G1Target { x, y }
    }

    pub fn double(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let x = self.x.clone();
        let y = self.y.clone();
        let double_y = y.add(builder, &y);
        let inv_double_y = double_y.inv(builder);
        let x_squared = x.mul(builder, &x);
        let double_x_squared = x_squared.add(builder, &x_squared);
        let triple_x_squared = double_x_squared.add(builder, &x_squared);
        let triple_xx_a = triple_x_squared.clone();
        let lambda = triple_xx_a.mul(builder, &inv_double_y);
        let lambda_squared = lambda.mul(builder, &lambda);
        let x_double = x.add(builder, &x);
        let x3 = lambda_squared.sub(builder, &x_double);
        let x_diff = x.sub(builder, &x3);
        let lambda_x_diff = lambda.mul(builder, &x_diff);
        let y3 = lambda_x_diff.sub(builder, &y);

        G1Target { x: x3, y: y3 }
    }

    pub fn add(&self, builder: &mut CircuitBuilder<F, D>, rhs: &Self) -> Self {
        let x1 = self.x.clone();
        let y1 = self.y.clone();
        let x2 = rhs.x.clone();
        let y2 = rhs.y.clone();

        let u = y2.sub(builder, &y1);
        let v = x2.sub(builder, &x1);
        let v_inv = v.inv(builder);
        let s = u.mul(builder, &v_inv);
        let s_squared = s.mul(builder, &s);
        let x_sum = x2.add(builder, &x1);
        let x3 = s_squared.sub(builder, &x_sum);
        let x_diff = x1.sub(builder, &x3);
        let prod = s.mul(builder, &x_diff);
        let y3 = prod.sub(builder, &y1);

        G1Target { x: x3, y: y3 }
    }

    pub fn conditional_add(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        p: &Self,
        b: &BoolTarget,
    ) -> Self {
        let sum = self.add(builder, p);

        let x = FqTarget::select(builder, &sum.x, &self.x, b);
        let y = FqTarget::select(builder, &sum.y, &self.y, b);

        Self { x, y }
    }

    pub fn pow_var_simple(&self, builder: &mut CircuitBuilder<F, D>, s: &FrTarget<F, D>) -> Self {
        let bits = builder.split_nonnative_to_bits(&s.target);

        let mut doubles = vec![];
        let mut v = self.clone();
        doubles.push(v.clone());
        for _ in 1..bits.len() {
            v = v.double(builder);
            doubles.push(v.clone());
        }

        assert_eq!(bits.len(), doubles.len());

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let rando = G1Affine::rand(&mut rng);
        let rando_t = G1Target::constant(builder, rando);
        let neg_rando = G1Target::constant(builder, -rando);
        let mut r = rando_t;

        for i in 0..bits.len() {
            r = r.conditional_add(builder, &doubles[i], &bits[i]);
        }

        r = r.add(builder, &neg_rando);

        r
    }
}

impl<F: RichField + Extendable<D>, const D: usize> G1Target<F, D> {
    pub fn to_vec(&self) -> Vec<Target> {
        self.x.to_vec().into_iter().chain(self.y.to_vec()).collect()
    }

    pub fn from_vec(builder: &mut CircuitBuilder<F, D>, input: &[Target]) -> Self {
        assert_eq!(input.len(), 16);
        let mut input = input.to_vec();
        let x_raw = input.drain(0..8).collect_vec();
        let y_raw = input;
        Self {
            x: FqTarget::from_vec(builder, &x_raw),
            y: FqTarget::from_vec(builder, &y_raw),
        }
    }

    pub fn set_witness(&self, pw: &mut PartialWitness<F>, value: &G1Affine) {
        self.x.set_witness(pw, &value.x);
        self.y.set_witness(pw, &value.y);
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Affine};
    use ark_std::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
    use rand::SeedableRng;

    use crate::fields::fr_target::FrTarget;

    use super::G1Target;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_g1_add() {
        let rng = &mut rand::thread_rng();
        let a = G1Affine::rand(rng);
        let b = G1Affine::rand(rng);
        let c_expected: G1Affine = (a + b).into();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = G1Target::constant(&mut builder, a);
        let b_t = G1Target::constant(&mut builder, b);
        let c_t = a_t.add(&mut builder, &b_t);
        let c_expected_t = G1Target::constant(&mut builder, c_expected);

        G1Target::connect(&mut builder, &c_expected_t, &c_t);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }

    #[test]
    fn test_g1_double() {
        let rng = &mut rand::thread_rng();
        let a = G1Affine::rand(rng);
        let c_expected: G1Affine = (a + a).into();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = G1Target::constant(&mut builder, a);
        let c_t = a_t.double(&mut builder);
        let c_expected_t = G1Target::constant(&mut builder, c_expected);

        G1Target::connect(&mut builder, &c_expected_t, &c_t);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }

    #[test]
    fn test_pow_var_simple_g1() {
        let rng = &mut rand::thread_rng();

        let p = G1Affine::rand(rng);
        let n = Fr::from(5);
        let r_expected: G1Affine = (p * n).into();

        let five_p: G1Affine = (p + p + p + p + p).into();
        assert_eq!(five_p, r_expected);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let p_t = G1Target::constant(&mut builder, p);
        let n_t = FrTarget::constant(&mut builder, n);

        let r_t = p_t.pow_var_simple(&mut builder, &n_t);
        let r_expected_t = G1Target::constant(&mut builder, r_expected);

        G1Target::connect(&mut builder, &r_t, &r_expected_t);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }

    #[test]
    fn test_rand_neg() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let rando = G1Affine::rand(&mut rng);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let rando_t = G1Target::constant(&mut builder, rando);
        let neg_rando = G1Target::constant(&mut builder, -rando);
        let mut r = rando_t;

        let a = G1Affine::rand(&mut rng);
        let a_t = G1Target::constant(&mut builder, a);

        let b = builder.constant_bool(true);
        r = r.conditional_add(&mut builder, &a_t, &b);
        r = r.add(&mut builder, &neg_rando);

        G1Target::connect(&mut builder, &r, &a_t);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }

    fn u64_to_binary_vec(a: u64, l: usize) -> Vec<bool> {
        let mut binary_vec = vec![false; l];
        let mut r = a;
        for i in 0..l {
            binary_vec[i] = r & 1 == 1;
            r >>= 1;
            if r == 0 {
                break;
            }
        }
        binary_vec
    }

    #[test]
    fn test_bit_split() {
        let n: u64 = 13131241945145145;
        let a = Fr::from(n);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = FrTarget::constant(&mut builder, a);
        let bits_t = builder.split_nonnative_to_bits(&a_t.target);

        let bits = u64_to_binary_vec(n, bits_t.len());

        let mut pw = PartialWitness::new();

        for i in 0..bits_t.len() {
            pw.set_bool_target(bits_t[i], bits[i]);
        }
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
    }
}
