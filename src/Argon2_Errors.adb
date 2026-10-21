package body Argon2_Errors with SPARK_Mode is

   function Get_Error_Message (Code : Interfaces.C.int) return Error_String is
   begin
      case Code is
         when   0 => return A_0;
         when  -1 => return A_1;
         when  -2 => return A_2;
         when  -3 => return A_3;
         when  -4 => return A_4;
         when  -5 => return A_5;
         when  -6 => return A_6;
         when  -7 => return A_7;
         when  -8 => return A_8;
         when  -9 => return A_9;
         when -10 => return A_10;
         when -11 => return A_11;
         when -12 => return A_12;
         when -13 => return A_13;
         when -14 => return A_14;
         when -15 => return A_15;
         when -16 => return A_16;
         when -17 => return A_17;
         when -18 => return A_18;
         when -19 => return A_19;
         when -20 => return A_20;
         when -21 => return A_21;
         when -22 => return A_22;
         when -23 => return A_23;
         when -24 => return A_24;
         when -25 => return A_25;
         when -26 => return A_26;
         when -27 => return A_27;
         when -28 => return A_28;
         when -29 => return A_29;
         when -30 => return A_30;
         when -31 => return A_31;
         when -32 => return A_32;
         when -33 => return A_33;
         when -34 => return A_34;
         when -35 => return A_35;
         when others => return A_Unk;
      end case;
   end Get_Error_Message;

end Argon2_Errors;
