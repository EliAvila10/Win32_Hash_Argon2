with Utilities,
     Interfaces,
     Interfaces.C,
     Argon2_Hash_Data,
     Wrapper_ZeroMemory;

procedure Win32_Hash_Argon2 is

   use Utilities,
       Interfaces,
       Interfaces.C,
       Argon2_Hash_Data;

   Password_1 : String := "Adaforum2026123!";
   Password_2 : String := "Adaforum20261231";

   Password_3 : String := "Adaforum2026123!";
   Password_4 : String := "Adaforum2026123!";

   Ok : Boolean;

   ---------------
   --  Example  --
   ---------------
   --  Hashes Hash_Pwd, then verifies Verify_Pwd against that hash.
   --  Both passwords are wiped right after being copied into the records.
   --  Ok = False only if hashing failed (nothing was verified).

   --    Example 1: verify with a DIFFERENT password  -> must fail.
   --    Example 2: verify with the SAME password     -> must succeed.
   --
   --  Password       Min -> 12, Max -> 512
   --  Bytes for salt Min -> 32, Max -> 256
   --  T_Cost         Min -> 1,  Max -> 10
   --  M_Cost         Min -> 16, Max -> 1_048_576
   --  T_Parallelism  Min -> 2,  Max -> 10
   --  Hash Len       Min -> 32, Max -> 128
   --  Main source of entropy: ProcessPrng, fallback BCryptGenRandom.

   procedure Example (Border     :        String;
                      Message    :        String;
                      Hash_Pwd   : in out String;
                      Verify_Pwd : in out String;
                      Ok         :    out Boolean)
   is

      --  Local records: each example starts from the default values, which
      --  already satisfy the Pre of
      --  Public_Hash
      --  (Password /= (Password'range => '0'), hash all '0', Status /= 0)
      --  and already satisfy the Pre of
      --  Public_Verify (Same = False, Status /= 0).

      --  It already start with default values such as:

      --  1. Salt bytes  => 32
      --  2. Cost_T      => 3
      --  3. M_Cost      => 65536
      --  4. Parallelism => 4
      --  5. Hash length => 32 bytes

      --  Hash and Hash_Length are limited (subtype) to support values
      --  from a minimum of 116 characters to a maximum of 550 characters.

      --  Hash Length has a minimum and maximum default value.
      --  If argon2 fails or returns something out of range,
      --  Constraint_error will be raised.

      --
      To_Hash   : Argon2_Hash_Data.Data;
      To_Verify : Argon2_Hash_Data.Verify_Data;

   begin

      Ok := False;

      T_IO.Put_Line (Item => Border);
      T_IO.Put_Line (Item => Message);
      T_IO.Put_Line (Item => Border);

      To_Hash.Password (1 .. Hash_Pwd'Length) := Hash_Pwd;
      To_Hash.Password_Length                 := Hash_Pwd'Length;

      To_Hash.Salt_Maximum := 32;
      --  Here you can add how many bytes you want for the salt.
      --  Min -> 32, Max -> 256
      --  By default are 32 bytes.

      --  We clear the password immediately after making a copy;
      --  the password in the record will be cleared within
      --  the 'Hash' and will return as all zeros.

      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => Hash_Pwd);
      --  Hash_Pwd := (others => '0');
      --  I'm commenting on this line so
      --  you can see the functionality of SecureZeroMemory.

      T_IO.New_Line;
      T_IO.Put_Line (Item => Password_Copying & Hash_Pwd);
      T_IO.New_Line;

      T_IO.Put_Line (Item => Hashing);
      T_IO.New_Line;

      Public_Hash (Item => To_Hash);

      if To_Hash.Status = 0 then

         T_IO.Put_Line
           (Item => Success & Interfaces.C.int'Image (To_Hash.Status));

         T_IO.New_Line;

         T_IO.Put_Line
           (Item => Password_M
            & To_Hash.Password (1 .. Positive (To_Hash.Password_Length)));

         T_IO.Put_Line
           (Item => Hash_M
           & To_Hash.Hash (1 .. Positive (To_Hash.Hash_Length)));
      else

         T_IO.Put_Line
           (Item => Failed & Interfaces.C.int'Image (To_Hash.Status));

         T_IO.New_Line;

         T_IO.Put_Line
           (Item => Password_M
            & To_Hash.Password (1 .. Positive (To_Hash.Password_Length)));

         T_IO.Put_Line
           (Item => Hash_M
            & To_Hash.Hash (1 .. Positive (To_Hash.Hash_Length)));
         return;

      end if;

      T_IO.New_Line;

      --  If this were a registration, after saving to the database you
      --  would clean the hash.

      --=====================================================================--

      T_IO.Put_Line (Item => Verifying);
      T_IO.New_Line;

      To_Verify.Password (1 .. Verify_Pwd'Length) := Verify_Pwd;
      To_Verify.Password_Length                   := Verify_Pwd'Length;

      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => Verify_Pwd);
      --  Verify_Pwd := (others => '0');

      T_IO.Put_Line (Item => Password_Copying & Verify_Pwd);
      T_IO.New_Line;

      To_Verify.Hash        := To_Hash.Hash;
      To_Verify.Hash_Length := To_Hash.Hash_Length;

      Public_Verify (Item => To_Verify);

      --  Whether the verification fails or not,
      --  the password and hash will all return as zero.

      T_IO.New_Line;

      if To_Verify.Status = 0 then
         T_IO.Put_Line
           (Item => Success & Interfaces.C.int'Image (To_Verify.Status));
      else
         T_IO.Put_Line
           (Item => Failed & Interfaces.C.int'Image (To_Verify.Status));
      end if;

      T_IO.New_Line;

      --  Two conditions on purpose: Status says the derivation worked,
      --  Same say the hash matched.
      if To_Verify.Status = 0
        and then To_Verify.Same
      then

         T_IO.Put_Line (Item => Successful);

      else

         T_IO.Put_Line (Item => Unsuccessful);

      end if;

      T_IO.Put_Line
        (Item => Password_M
         & To_Verify.Password (1 .. Positive (To_Verify.Password_Length)));

      T_IO.Put_Line
        (Item => Password_M
         & To_Verify.Hash (1 .. Positive (To_Verify.Hash_Length)));

      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Hash.Password);
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Hash.Hash);
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Verify.Password);
      Wrapper_ZeroMemory.SecureZeroMemory_Strings (Item => To_Verify.Hash);

      Ok := True;

   end Example;

begin

   Example (Border     => C1,
            Message    => Example_Message_1,
            Hash_Pwd   => Password_1,
            Verify_Pwd => Password_2,
            Ok         => Ok);

   if not Ok then
      return;
   end if;

   T_IO.New_Line;
   T_IO.New_Line;

   Example (Border     => C2,
            Message    => Example_Message_2,
            Hash_Pwd   => Password_3,
            Verify_Pwd => Password_4,
            Ok         => Ok);

end Win32_Hash_Argon2;
