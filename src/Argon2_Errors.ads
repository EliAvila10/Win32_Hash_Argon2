with Interfaces.C;

package Argon2_Errors with SPARK_Mode is

   use Interfaces.C;

   pragma Style_Checks ("-M");
   pragma Assertion_Policy (Check);

   subtype Error_String is String (1 .. 32);

   A_0   : constant Error_String := "ARGON2_OK                       ";
   A_1   : constant Error_String := "ARGON2_OUTPUT_PTR_NULL          ";
   A_2   : constant Error_String := "ARGON2_OUTPUT_TOO_SHORT         ";
   A_3   : constant Error_String := "ARGON2_OUTPUT_TOO_LONG          ";
   A_4   : constant Error_String := "ARGON2_PWD_TOO_SHORT            ";
   A_5   : constant Error_String := "ARGON2_PWD_TOO_LONG             ";
   A_6   : constant Error_String := "ARGON2_SALT_TOO_SHORT           ";
   A_7   : constant Error_String := "ARGON2_SALT_TOO_LONG            ";
   A_8   : constant Error_String := "ARGON2_AD_TOO_SHORT             ";
   A_9   : constant Error_String := "ARGON2_AD_TOO_LONG              ";
   A_10  : constant Error_String := "ARGON2_SECRET_TOO_SHORT         ";
   A_11  : constant Error_String := "ARGON2_SECRET_TOO_LONG          ";
   A_12  : constant Error_String := "ARGON2_TIME_TOO_SMALL           ";
   A_13  : constant Error_String := "ARGON2_TIME_TOO_LARGE           ";
   A_14  : constant Error_String := "ARGON2_MEMORY_TOO_LITTLE        ";
   A_15  : constant Error_String := "ARGON2_MEMORY_TOO_MUCH          ";
   A_16  : constant Error_String := "ARGON2_LANES_TOO_FEW            ";
   A_17  : constant Error_String := "ARGON2_LANES_TOO_MANY           ";
   A_18  : constant Error_String := "ARGON2_PWD_PTR_MISMATCH         ";
   A_19  : constant Error_String := "ARGON2_SALT_PTR_MISMATCH        ";
   A_20  : constant Error_String := "ARGON2_SECRET_PTR_MISMATCH      ";
   A_21  : constant Error_String := "ARGON2_AD_PTR_MISMATCH          ";
   A_22  : constant Error_String := "ARGON2_MEMORY_ALLOCATION_ERROR  ";
   A_23  : constant Error_String := "ARGON2_FREE_MEMORY_CBK_NULL     ";
   A_24  : constant Error_String := "ARGON2_ALLOCATE_MEMORY_CBK_NULL ";
   A_25  : constant Error_String := "ARGON2_INCORRECT_PARAMETER      ";
   A_26  : constant Error_String := "ARGON2_INCORRECT_TYPE           ";
   A_27  : constant Error_String := "ARGON2_OUT_PTR_MISMATCH         ";
   A_28  : constant Error_String := "ARGON2_THREADS_TOO_FEW          ";
   A_29  : constant Error_String := "ARGON2_THREADS_TOO_MANY         ";
   A_30  : constant Error_String := "ARGON2_MISSING_ARGS             ";
   A_31  : constant Error_String := "ARGON2_ENCODING_FAIL            ";
   A_32  : constant Error_String := "ARGON2_DECODING_FAIL            ";
   A_33  : constant Error_String := "ARGON2_THREAD_FAIL              ";
   A_34  : constant Error_String := "ARGON2_DECODING_LENGTH_FAIL     ";
   A_35  : constant Error_String := "ARGON2_VERIFY_MISMATCH          ";
   A_Unk : constant Error_String := "ARGON2_UNKNOWN_ERROR            ";

   --  @return Argon2 Error
   function Get_Error_Message (Code : Interfaces.C.int) return Error_String
     with Global => null,
     Post =>
       (case Code is
          when   0    => Get_Error_Message'Result = A_0,
            when  -1    => Get_Error_Message'Result = A_1,
              when  -2    => Get_Error_Message'Result = A_2,
                when  -3    => Get_Error_Message'Result = A_3,
                  when  -4    => Get_Error_Message'Result = A_4,
                    when  -5    => Get_Error_Message'Result = A_5,
                      when  -6    => Get_Error_Message'Result = A_6,
                        when  -7    => Get_Error_Message'Result = A_7,
                          when  -8    => Get_Error_Message'Result = A_8,
                            when  -9    => Get_Error_Message'Result = A_9,
                              when -10    => Get_Error_Message'Result = A_10,
                                when -11    => Get_Error_Message'Result = A_11,
                                  when -12    => Get_Error_Message'Result = A_12,
                                    when -13    => Get_Error_Message'Result = A_13,
                                      when -14    => Get_Error_Message'Result = A_14,
                                        when -15    => Get_Error_Message'Result = A_15,
                                          when -16    => Get_Error_Message'Result = A_16,
                                            when -17    => Get_Error_Message'Result = A_17,
                                              when -18    => Get_Error_Message'Result = A_18,
                                                when -19    => Get_Error_Message'Result = A_19,
                                                  when -20    => Get_Error_Message'Result = A_20,
                                                    when -21    => Get_Error_Message'Result = A_21,
                                                      when -22    => Get_Error_Message'Result = A_22,
                                                        when -23    => Get_Error_Message'Result = A_23,
                                                          when -24    => Get_Error_Message'Result = A_24,
                                                            when -25    => Get_Error_Message'Result = A_25,
                                                              when -26    => Get_Error_Message'Result = A_26,
                                                                when -27    => Get_Error_Message'Result = A_27,
                                                                  when -28    => Get_Error_Message'Result = A_28,
                                                                    when -29    => Get_Error_Message'Result = A_29,
                                                                      when -30    => Get_Error_Message'Result = A_30,
                                                                        when -31    => Get_Error_Message'Result = A_31,
                                                                          when -32    => Get_Error_Message'Result = A_32,
                                                                            when -33    => Get_Error_Message'Result = A_33,
                                                                              when -34    => Get_Error_Message'Result = A_34,
                                                                                when -35    => Get_Error_Message'Result = A_35,
                                                                                  when others => Get_Error_Message'Result = A_Unk);

end Argon2_Errors;
