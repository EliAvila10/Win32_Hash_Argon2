with Utilities,
     Ada.Exceptions,
     Argon2_Errors,
     Wrapper_ProcessPrng,
     Wrapper_BcryptGenRandom;

package body Argon2_Hash_Data with SPARK_Mode is

   use Utilities,
       Argon2_Errors,
       Wrapper_ZeroMemory;

   ------------------------------
   --  Is Valid Argon2 Format  --
   ------------------------------
   function Is_Valid_Argon2_Format
     (Encoded_Hash : New_Hash;
      Valid_Len    : New_Hash_Length)
      return Boolean
   is
      P_Index : Natural := 0;
   begin
      if Encoded_Hash (1 .. 10) /= "$argon2id$" then
         return False;
      end if;

      for I in 1 .. Valid_Len - 1 loop
         if Encoded_Hash (I) = 'p' and then Encoded_Hash (I + 1) = '=' then
            P_Index := I;
            exit;
         end if;
      end loop;

      if P_Index = 0 or else P_Index + 2 > Valid_Len then
         return False;
      end if;

      declare
         All_Zeros : Boolean := True;
      begin
         for I in P_Index + 2 .. Valid_Len loop
            if Encoded_Hash (I) /= '0' then
               All_Zeros := False;
               exit;
            end if;
         end loop;

         if All_Zeros then
            return False;
         end if;
      end;

      return True;
   end Is_Valid_Argon2_Format;

   ------------
   --  Hash  --
   ------------
   procedure Hash (Item : in out Data)
     with SPARK_Mode => off
   is

      Salt        : BUFFER_RNG (0 .. Item.Salt_Maximum - 1) := (others => 0);
      Status      : NTSTATUS := NTSTATUS'Last;
      Real_Length : C_Size_T := Real_Length_Valid'First;

      Argon2_Failed      : exception;
      Entropy_Salt_Error : exception;

   begin

      begin

         Wrapper_ProcessPrng.ProcessPrng_Public
           (Buffer => Salt,
            Status => Status);

         if Status /= 1 then

            SecureZeroMemory_Bytes (Item => Salt);
            Item.Status := BOOL'Last;
            Salt        := (others => 0);

            Wrapper_BcryptGenRandom.BcryptGenRandom_Public
              (Buffer => Salt,
               Status => Status);

            if Status /= 0 then

               SecureZeroMemory_Strings (Item => Item.Password);
               Item.Password := (others => '0');

               SecureZeroMemory_Bytes (Item => Salt);
               Item.Status := BOOL'Last;
               Salt        := (others => 0);

               raise Entropy_Salt_Error with E_Providers;

            end if;
         end if;

         if Status in 0 .. 1 then

            Real_Length := Argon2_Encoded_Len
              (T_Cost      => Item.T_Cost,
               M_Cost      => Item.M_Cost,
               Parallelism => Item.Parallelism,
               Salt_Len    => Salt_Max_Bytes_U (Salt'Length),
               Hash_Len    => Hash_Len_Bytes_U (Item.Hash_Len_Pure));

            Item.Hash_Length := Positive (Real_Length);
            Real_Length      := Real_Length_Valid'First;

            Item.Status := Argon2id_Hash_Encoded
              (T_Cost      => Item.T_Cost,
               M_Cost      => Item.M_Cost,
               Parallelism => Item.Parallelism,
               Pwd         => Item.Password (Item.Password'First)'Address,
               Pwd_Len     => C_Size_T      (Item.Password_Length),
               Salt        => Salt          (Salt'First)'Address,
               Salt_Len    => C_Size_T      (Salt'Length),
               Hash_Len    => Item.Hash_Len_Pure,
               Encoded     => Item.Hash     (Item.Hash'First)'Address,
               Encoded_Len => C_Size_T      (Item.Hash'Length));

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Bytes   (Item => Salt);

            Item.Password := (others => '0');
            Salt          := (others => 0);

            if Item.Status /= 0 then
               raise Argon2_Failed
                 with Get_Error_Message (Code => Item.Status);
            end if;

            if not Is_Valid_Argon2_Format
              (Encoded_Hash => Item.Hash,
               Valid_Len    => Item.Hash_Length)
            then
               SecureZeroMemory_Strings (Item => Item.Hash);
               Item.Hash := (others => '0');
               raise Argon2_Failed with E_Format;
            end if;

         else
            raise Entropy_Salt_Error with E_Providers;
         end if;

      exception

         when S : Entropy_Salt_Error =>

            --  if the entropy providers for the salt fail,
            --  everything is cleaned up even if it hasn't been
            --  used and the return value will be either
            --  the input value which must be /= 0 or Bool'Last

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Bytes   (Item => Salt);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);
            Item.Status   := BOOL'Last;

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => S));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => S));

         when C : Constraint_Error =>

            --  If a constraint error occurs,
            --  it would be due to either direct manipulation,
            --  an unexpected system failure,
            --  or something within the argon2 .dll file.

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Bytes   (Item => Salt);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);
            Item.Status   := BOOL'Last;

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => C));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => C));

         when A : Argon2_Failed =>

            --  if an internal failure occurs within the argon2 .dll

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Bytes   (Item => Salt);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => A));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => A));

         when O : others =>

            --  If any other unexpected error occurs

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Bytes   (Item => Salt);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            Salt          := (others => 0);

            if Item.Status /= 0 then

               T_IO.Put_Line
                 (Item => Argon_Error
                  & Argon2_Errors.Get_Error_Message (Code => Item.Status));

            end if;

            Item.Status := BOOL'Last;

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => O));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => O));

      end;

   end Hash;

   -------------------
   --  Public Hash  --
   -------------------
   procedure Public_Hash (Item : in out Data) is
   begin
      Hash (Item => Item);
   end Public_Hash;

   --========================================================================--

   --------------
   --  Verify  --
   --------------
   procedure Verify (Item : in out Verify_Data)
     with SPARK_Mode => off
   is

      H             : String (1 .. Item.Hash_Length) := (others => '0');
      Argon2_Failed : exception;

   begin

      begin

         H (1 .. Item.Hash_Length) := Item.Hash (1 .. Item.Hash_Length);
         SecureZeroMemory_Strings (Item => Item.Hash);
         Item.Hash := (others => '0');

         Item.Status := Argon2id_Verify
           (Encoded => H (H'First)'Address,
            Pwd     => Item.Password (Item.Password'First)'Address,
            Pwd_Len => C_Size_T      (Item.Password_Length));

         SecureZeroMemory_Strings (Item => Item.Password);
         SecureZeroMemory_Strings (Item => H);

         Item.Password := (others => '0');
         H             := (others => '0');

         if Item.Status /= 0 then
            raise Argon2_Failed
              with Get_Error_Message (Code => Item.Status);
         else
            Item.Same := (Item.Status = 0);
         end if;

      exception

         when C : Constraint_Error =>

            --  If a constraint error occurs,
            --  it would be due to either direct manipulation,
            --  an unexpected system failure,
            --  or something within the argon2 .dll file.

            Item.Same := False;

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Strings (Item => H);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            H             := (others => '0');
            Item.Status   := BOOL'Last;

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => C));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => C));

         when A : Argon2_Failed =>

            --  if an internal failure occurs within the argon2 .dll

            Item.Same := False;

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Strings (Item => H);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            H             := (others => '0');

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => A));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => A));

         when O : others =>

            --  If any other unexpected error occurs
            --  The postcondition will fail because
            --  I'm forcing Item.Same := False, and if Item.Status = 0,
            --  it will violate the postcondition because
            --  it doesn't match Item.Same = (Item.Status = 0),
            --  which means there could have been a serious system failure,
            --  tampering, a problem with the argon2 .dll,
            --  or something extremely unexpected.

            Item.Same := False;

            SecureZeroMemory_Strings (Item => Item.Password);
            SecureZeroMemory_Strings (Item => Item.Hash);
            SecureZeroMemory_Strings (Item => H);

            Item.Password := (others => '0');
            Item.Hash     := (others => '0');
            H             := (others => '0');

            if Item.Status /= 0 then
               T_IO.Put_Line
                 (Item => Argon_Error
                  & Get_Error_Message (Code => Item.Status));
            end if;

            T_IO.New_Line;

            T_IO.Put_Line
              (Item => E_Message & Ada.Exceptions.Exception_Message (X => O));

            T_IO.Put_Line
              (Item => E_Name & Ada.Exceptions.Exception_Name (X => O));

      end;

   end Verify;

   ---------------------
   --  Public Verify  --
   ---------------------
   procedure Public_Verify (Item : in out Verify_Data) is
   begin
      Verify (Item => Item);
   end Public_Verify;

end Argon2_Hash_Data;
