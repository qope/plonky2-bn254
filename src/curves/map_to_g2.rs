use ark_bn254::{Fq, Fq2, G2Affine};
use ark_ff::Field;
use ark_ff::MontFp;
use ark_std::Zero;
use num_bigint::BigUint;
use num_traits::One;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::fields::fq2_target::Fq2Target;

use super::g2curve_target::G2Target;

fn or_circuit<F, const D: usize>(
    a: BoolTarget,
    b: BoolTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> BoolTarget
where
    F: RichField + Extendable<D>,
{
    // a = 0, b = 0 => 0
    // a = 1, b = 0 => 1
    // a = 0, b = 1 => 1
    // a = 1, b = 1 => 1
    // or(a, b) = 1 - (1-a)*(1-b) = a+b-ab
    let a_plus_b = builder.add(a.target, b.target);
    let c = builder.arithmetic(F::NEG_ONE, F::ONE, a.target, b.target, a_plus_b);
    BoolTarget::new_unsafe(c)
}

#[allow(non_snake_case)]
pub fn map_to_g2_without_cofactor_mul(u: Fq2) -> G2Affine {
    // constants
    let Z = Fq2::one();
    let B = Fq2::new(
        MontFp!("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
        MontFp!("266929791119991161246907387137283842545076965332900288569378510910307636690"),
    );
    let g = |x: Fq2| -> Fq2 { x * x * x + B };
    let gz = g(Z);
    let neg_two: BigUint = Fq::from(-2).into();
    let inv_fq = |x: Fq| -> Fq { x.pow(neg_two.to_u64_digits()) };
    let inv0 = |x: Fq2| -> Fq2 {
        let t0 = inv_fq(x.c0 * x.c0 + x.c1 * x.c1);
        let bx = x.c0 * t0;
        let by = -x.c1 * t0;
        Fq2::new(bx, by)
    };

    let sgn0_fq = |x: Fq| -> bool {
        let y: BigUint = x.into();
        y.to_u32_digits()[0] & 1 == 1
    };
    let sgn0 = |x: Fq2| -> bool {
        let sgn0_x = sgn0_fq(x.c0);
        let zero_0 = x.c0.is_zero();
        let sgn0_y = sgn0_fq(x.c1);
        sgn0_x || (zero_0 && sgn0_y)
    };
    let neg_two_by_z = -Z / (Fq2::from(2));
    let tv4 = (-gz * Fq2::from(3) * Z * Z).sqrt().unwrap();
    let tv6 = -Fq2::from(4) * gz / (Fq2::from(3) * Z * Z);
    // end of constants

    let tv1 = u * u * gz;
    let tv2 = Fq2::one() + tv1;
    let tv1 = Fq2::one() - tv1;
    let tv3 = inv0(tv1 * tv2);
    let tv5 = u * tv1 * tv3 * tv4;
    let x1 = neg_two_by_z - tv5;
    let x2 = neg_two_by_z + tv5;
    let x3 = Z + tv6 * (tv2 * tv2 * tv3) * (tv2 * tv2 * tv3);
    let is_gx1_sq = g(x1).legendre().is_qr();
    let is_gx2_sq = g(x2).legendre().is_qr();
    // let is_gx3_sq = g(x3).legendre().is_qr();

    // dbg!(is_gx1_sq, is_gx2_sq, is_gx3_sq);

    let x: Fq2;
    let mut y: Fq2;

    if is_gx1_sq {
        x = x1;
        y = g(x1).sqrt().unwrap();
    } else if is_gx2_sq {
        x = x2;
        y = g(x2).sqrt().unwrap();
    } else {
        x = x3;
        y = g(x3).sqrt().unwrap();
    }

    if sgn0(u) != sgn0(y) {
        y = -y;
    }

    assert!(g(x) == y * y);

    G2Affine::new_unchecked(x, y)
}

#[allow(non_snake_case)]
pub fn map_to_g2_without_cofactor_mul_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    u: &Fq2Target<F, D>,
) -> G2Target<F, D> {
    // constants
    let Z = Fq2::one();
    let B = Fq2::new(
        MontFp!("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
        MontFp!("266929791119991161246907387137283842545076965332900288569378510910307636690"),
    );
    let g = |x: Fq2| -> Fq2 { x * x * x + B };
    let g_target = |x: &Fq2Target<F, D>, builder: &mut CircuitBuilder<F, D>| -> Fq2Target<F, D> {
        let x_cub = x.mul(builder, &x).mul(builder, &x);
        let b = Fq2Target::constant(builder, B);
        let x_cub_plus_b = x_cub.add(builder, &b);
        x_cub_plus_b
    };
    let gz = g(Z);
    let neg_two_by_z = -Z / (Fq2::from(2));
    let tv4 = (-gz * Fq2::from(3) * Z * Z).sqrt().unwrap();
    let tv6 = -Fq2::from(4) * gz / (Fq2::from(3) * Z * Z);
    // end of constants
    let Z = Fq2Target::constant(builder, Z);
    let gz = Fq2Target::constant(builder, gz);
    let tv4 = Fq2Target::constant(builder, tv4);
    let tv6 = Fq2Target::constant(builder, tv6);
    let neg_two_by_z = Fq2Target::constant(builder, neg_two_by_z);
    let one = Fq2Target::constant(builder, Fq2::one());

    let tv1 = u.mul(builder, &u).mul(builder, &gz);
    let tv2 = one.add(builder, &tv1);
    let tv1 = one.sub(builder, &tv1);
    let tv3 = tv1.mul(builder, &tv2).inv0(builder);
    let tv5 = u.mul(builder, &tv1).mul(builder, &tv3).mul(builder, &tv4);
    let x1 = neg_two_by_z.sub(builder, &tv5);
    let x2 = neg_two_by_z.add(builder, &tv5);
    let tv2tv2tv3 = tv2.mul(builder, &tv2).mul(builder, &tv3);
    let tv2tv2tv3_sq = tv2tv2tv3.mul(builder, &tv2tv2tv3);
    let tv6_tv2tv2tv3_sq = tv6.mul(builder, &tv2tv2tv3_sq);
    let x3 = Z.add(builder, &tv6_tv2tv2tv3_sq);
    let gx1 = g_target(&x1, builder);
    let gx2 = g_target(&x2, builder);
    let is_gx1_sq = gx1.is_square(builder);
    let is_gx2_sq = gx2.is_square(builder);

    let x1_or_x2 = Fq2Target::select(builder, &x1, &x2, &is_gx1_sq);
    let isgx1_or_isgx2 = or_circuit(is_gx1_sq, is_gx2_sq, builder);
    let x = Fq2Target::select(builder, &x1_or_x2, &x3, &isgx1_or_isgx2);

    let gx = g_target(&x, builder);
    let sgn_u = u.sgn0(builder);
    let y = gx.sqrt_with_sgn(builder, sgn_u);

    G2Target::new(x, y)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq2;
    use ark_std::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        curves::map_to_g2::{
            map_to_g2_without_cofactor_mul, map_to_g2_without_cofactor_mul_circuit,
        },
        fields::fq2_target::Fq2Target,
    };

    #[test]
    #[allow(non_snake_case)]
    fn test_map_to_curve() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let rng = &mut rand::thread_rng();
        let a: Fq2 = Fq2::rand(rng);
        let p_expected = map_to_g2_without_cofactor_mul(a);
        let x_expected = p_expected.x;
        let y_expected = p_expected.y;

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_t = Fq2Target::constant(&mut builder, a);
        let p_t = map_to_g2_without_cofactor_mul_circuit(&mut builder, &a_t);
        let x_t = p_t.x;
        let y_t = p_t.y;
        let x_expected_t = Fq2Target::constant(&mut builder, x_expected);
        let y_expected_t = Fq2Target::constant(&mut builder, y_expected);

        Fq2Target::connect(&mut builder, &x_t, &x_expected_t);
        Fq2Target::connect(&mut builder, &y_t, &y_expected_t);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits());
        let _proof = data.prove(pw);
    }
}
