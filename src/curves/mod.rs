use std::marker::PhantomData;

use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::get_gate_tag_impl;
use plonky2::read_gate_impl;
use plonky2::{
    field::extension::Extendable,
    gadgets::{
        arithmetic::EqualityGenerator,
        arithmetic_extension::QuotientGeneratorExtension,
        range_check::LowHighGenerator,
        split_base::BaseSumGenerator,
        split_join::{SplitGenerator, WireSplitGenerator},
    },
    gates::{
        arithmetic_base::ArithmeticBaseGenerator,
        arithmetic_extension::ArithmeticExtensionGenerator, base_sum::BaseSplitGenerator,
        coset_interpolation::InterpolationGenerator, exponentiation::ExponentiationGenerator,
        lookup::LookupGenerator, lookup_table::LookupTableGenerator,
        multiplication_extension::MulExtensionGenerator, poseidon::PoseidonGenerator,
        poseidon_mds::PoseidonMdsGenerator, random_access::RandomAccessGenerator,
        reducing::ReducingGenerator,
    },
    hash::hash_types::RichField,
    impl_gate_serializer, impl_generator_serializer,
    iop::generator::{
        ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
    },
    plonk::config::{AlgebraicHasher, GenericConfig},
    recursion::dummy_circuit::DummyProofGenerator,
    util::serialization::{GateSerializer, WitnessGeneratorSerializer},
};

use plonky2::get_generator_tag_impl;
use plonky2::read_generator_impl;
use plonky2_crypto::u32::gates::add_many_u32::U32AddManyGate;
use plonky2_crypto::u32::gates::arithmetic_u32::U32ArithmeticGate;
use plonky2_crypto::u32::gates::comparison::ComparisonGate;
use plonky2_crypto::u32::gates::interleave_u32::U32InterleaveGate;
use plonky2_crypto::u32::gates::range_check_u32::U32RangeCheckGate;
use plonky2_crypto::u32::gates::subtraction_u32::U32SubtractionGate;
use plonky2_crypto::u32::gates::uninterleave_to_b32::UninterleaveToB32Gate;
use plonky2_crypto::u32::gates::uninterleave_to_u32::UninterleaveToU32Gate;
use plonky2_crypto::u32::gates::{
    add_many_u32::U32AddManyGenerator, arithmetic_u32::U32ArithmeticGenerator,
    comparison::ComparisonGenerator, range_check_u32::U32RangeCheckGenerator,
    subtraction_u32::U32SubtractionGenerator,
};
use plonky2_ecdsa::gadgets::{
    glv::GLVDecompositionGenerator,
    nonnative::{
        NonNativeAdditionGenerator, NonNativeInverseGenerator, NonNativeMultiplicationGenerator,
        NonNativeSubtractionGenerator,
    },
};

use crate::fields::bn254base::Bn254Base;
pub mod g1curve_target;
pub mod g2curve_target;
pub mod map_to_g2;

/// Sets RUST_LOG=debug and initializes the logger
/// if it hasn't been enabled already.
#[cfg(test)]
pub(crate) fn init_logging() {
    use log::{log_enabled, Level, LevelFilter};
    use std::env;
    use std::io::Write;
    if !log_enabled!(Level::Debug) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "    {}", record.args()))
            .try_init();
        log::set_max_level(LevelFilter::Debug);
    }
}

pub struct BN254GeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for BN254GeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        HashGeneratorSerializer<F, C, D>,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        CopyGenerator,
        DummyProofGenerator<F, C, D>,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        MulExtensionGenerator<F,D>,
        SplitGenerator,
        WireSplitGenerator,
        // hash + ecdsa generators added
        GLVDecompositionGenerator<F,D>,
        NonNativeSubtractionGenerator<F,D,Bn254Base>,
        NonNativeInverseGenerator<F,D,Bn254Base>,
        NonNativeMultiplicationGenerator<F,D,Bn254Base>,
        NonNativeAdditionGenerator<F,D,Bn254Base>,
        U32RangeCheckGenerator<F,D,>,
        U32AddManyGenerator<F,D>,
        U32SubtractionGenerator<F,D>,
        U32ArithmeticGenerator<F,D>,
        ComparisonGenerator<F,D>
    }
}

pub struct BN254GateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for BN254GateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        //hash gates
        U32AddManyGate<F,D>,
        U32ArithmeticGate<F, D>,
        ComparisonGate<F, D>,
        U32InterleaveGate,
        U32RangeCheckGate<F,D>,
        U32SubtractionGate<F,D>,
        UninterleaveToB32Gate,
        UninterleaveToU32Gate
        // ecdsa
    }
}
