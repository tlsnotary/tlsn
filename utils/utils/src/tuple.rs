/// A trait for transposing a tuple of options into an option of a tuple.
pub trait TupleTranspose {
    /// The output type of the transpose operation.
    type Output;

    /// Transposes a tuple of options into an option of a tuple.
    fn transpose(self) -> Option<Self::Output>;
}

macro_rules! impl_tuple_option_transpose {
    (($($ty:ident),*), ($($inner:ident),*)) => {
        impl<$($ty),*> TupleTranspose for ($(Option<$ty>,)*)
        {
            type Output = ($($ty,)*);

            fn transpose(self) -> Option<($($ty,)*)> {
                match self {
                    ($(Some($inner),)*) => Some(($($inner,)*)),
                    _ => None,
                }
            }
        }
    };
}

impl_tuple_option_transpose!((T0, T1), (t0, t1));
impl_tuple_option_transpose!((T0, T1, T2), (t0, t1, t2));
impl_tuple_option_transpose!((T0, T1, T2, T3), (t0, t1, t2, t3));
impl_tuple_option_transpose!((T0, T1, T2, T3, T4), (t0, t1, t2, t3, t4));
impl_tuple_option_transpose!((T0, T1, T2, T3, T4, T5), (t0, t1, t2, t3, t4, t5));
impl_tuple_option_transpose!((T0, T1, T2, T3, T4, T5, T6), (t0, t1, t2, t3, t4, t5, t6));
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7),
    (t0, t1, t2, t3, t4, t5, t6, t7)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14)
);
impl_tuple_option_transpose!(
    (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15),
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15)
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose_some() {
        let a = Some(1);
        let b = Some("hello");

        assert!((a, b).transpose().is_some());
    }

    #[test]
    fn test_transpose_none() {
        let a = Some(1);
        let b: Option<&str> = None;

        assert!((a, b).transpose().is_none());
    }
}
