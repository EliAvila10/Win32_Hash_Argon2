with System,
     Interfaces,
     Interfaces.C,
     Ada.Text_IO,
     Wrapper_ZeroMemory,
     Windows_Data_Types;

package Argon2_Hash_Data with SPARK_Mode is

   use System,
       Interfaces,
       Interfaces.C,
       Windows_Data_Types;

   pragma Assertion_Policy (Check);

   subtype Pswd              is String (1 .. 512)
     with Dynamic_Predicate => (for all P of Pswd => P in '!' .. '~');

   subtype Pswd_Length       is Interfaces.C.size_t range
     12 .. Interfaces.C.size_t (Pswd'Last);

   subtype Salt_Max_Bytes    is Interfaces.C.size_t   range 32 .. 256;
   subtype Salt_Max_Bytes_U  is Interfaces.C.unsigned range
     Interfaces.C.unsigned (Salt_Max_Bytes'First)
     .. Interfaces.C.unsigned (Salt_Max_Bytes'Last);

   subtype New_Hash          is String (1 .. 550)
     with Dynamic_Predicate => (for all H of New_Hash => H in '!' .. '~');

   subtype New_Hash_Length   is Positive range 116 .. New_Hash'Length;

   subtype Real_Length_Valid is Interfaces.C.size_t range
     Interfaces.C.size_t (New_Hash_Length'First)
     .. Interfaces.C.size_t (New_Hash_Length'Last);

   subtype Hash_Len_Bytes    is Interfaces.C.size_t   range 32 .. 128;
   subtype Hash_Len_Bytes_U  is Interfaces.C.unsigned range
     Interfaces.C.unsigned (Hash_Len_Bytes'First)
     .. Interfaces.C.unsigned (Hash_Len_Bytes'Last);

   subtype T_Parallelism     is Interfaces.C.unsigned range 2 .. 10;

   subtype Time_Cost_Range   is Interfaces.C.unsigned range 1 .. 10;
   subtype Memory_Cost_Range is Interfaces.C.unsigned range 16 .. 1048576;

   --========================================================================--

   --  Password       Min -> 12, Max -> 512
   --  Bytes for salt Min -> 32, Max -> 256
   --  T_Cost         Min -> 1,  Max -> 10
   --  M_Cost         Min -> 16, Max -> 1_048_576
   --  T_Parallelism  Min -> 2,  Max -> 10
   --  Hash Len       Min -> 32, Max -> 128
   --  Main source of entropy: ProcessPrng, fallback BCryptGenRandom.

   type Data is record
      Password        : Pswd                 := (others => '0');
      Password_Length : Pswd_Length          := Pswd_Length'First;

      Salt_Maximum    : Salt_Max_Bytes      := Salt_Max_Bytes'First;

      T_Cost          : Time_Cost_Range     := 3;
      M_Cost          : Memory_Cost_Range   := 65536;
      Parallelism     : T_Parallelism       := 4;
      Hash_Len_Pure   : Hash_Len_Bytes      := Hash_Len_Bytes'First;

      Hash            : New_Hash            := (others => '0');
      Hash_Length     : New_Hash_Length     := New_Hash_Length'First;

      Status          : BOOL                := BOOL'Last;
   end record;

   --  Performs zero-copy runtime validation of an encoded Argon2 hash.
   --
   --  @param Encoded_Hash The string buffer containing the hash.
   --  @param Valid_Len    The active length of the encoded hash string.
   --  @return True if format is valid, False otherwise.
   --
   --  @note Postconditions:
   --  - If True, guarantees prefix "$argon2id$" and delimiter "p=" exist.
   function Is_Valid_Argon2_Format
     (Encoded_Hash : New_Hash;
      Valid_Len    : New_Hash_Length)
      return Boolean
      with Global => null,
      Post =>
        (if Is_Valid_Argon2_Format'Result then
           Encoded_Hash (1 .. 10) = "$argon2id$"
         and then (for some I in 1 .. Valid_Len - 1 =>
                     Encoded_Hash (I) = 'p'
                 and then Encoded_Hash (I + 1) = '='));

   --========================================================================--

   --  Generates a secure Argon2id encoded hash using entropy and C bindings.
   --
   --  @param Item The data structure containing credentials and settings.
   --
   --  @note Preconditions:
   --  - Input password cannot be empty or all NULs.
   --  - Hash buffer must be fully initialized to '0' before calling.
   --  - Status must be non-zero.
   --
   --  @note Postconditions:
   --  - The input Password is guaranteed to be securely wiped ('0').
   --  - If Status is success (0), Hash passes structural validation.
   --  - If Status fails, Hash buffer is completely zero.
   --
   --  @see Wrapper_ZeroMemory.Secure_Clean
   procedure Public_Hash (Item : in out Data)
     with Global  => (In_Out => (Ada.Text_IO.File_System,
                              Wrapper_ZeroMemory.Secure_Clean)),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                Wrapper_ZeroMemory.Secure_Clean =>
                  (Item, Wrapper_ZeroMemory.Secure_Clean),
                Ada.Text_IO.File_System =>+ (Item)),

     Pre     => Item.Password /= (Item.Password'Range => ASCII.NUL)
     and then (for all H of Item.Hash => H = '0')
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then
       (if Item.Status = 0 then
          Is_Valid_Argon2_Format (Encoded_Hash => Item.Hash,
                                  Valid_Len    => Item.Hash_Length)
        else
          (for all C of Item.Hash => C = '0'));

   --========================================================================--

   type Verify_Data is record
      Password        : Pswd              := (others => '0');
      Password_Length : Pswd_Length       := Pswd_Length'First;

      Hash            : New_Hash          := (others => '0');
      Hash_Length     : New_Hash_Length   := New_Hash_Length'First;

      Status          : BOOL              := BOOL'Last;
      Same            : Boolean           := False;
   end record;

   --  Executes secure verification of a candidate password against a hash.
   --
   --  @param Item The verification structure containing password and hash.
   --
   --  @note Preconditions:
   --  - Input password and hash must not be all zeros.
   --  - Item.Same must be initialized to False.
   --
   --  @note Postconditions:
   --  - Input Password and Hash are guaranteed to be securely wiped ('0').
   --  - Item.Same evaluates to True if and only if Status is success (0).
   --
   --  @see Wrapper_ZeroMemory.Secure_Clean
   procedure Public_Verify (Item : in out Verify_Data)
     with Global  => (In_Out => (Ada.Text_IO.File_System,
                              Wrapper_ZeroMemory.Secure_Clean)),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                Wrapper_ZeroMemory.Secure_Clean =>
                  (Item, Wrapper_ZeroMemory.Secure_Clean),
                Ada.Text_IO.File_System =>+ (Item)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then Item.Hash /= (Item.Hash'Range => '0')
     and then Item.Same = False,

     Post    => (for all P of Item.Password => P = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Same = (Item.Status = 0)
     and then (if Item.Same then Item.Status = 0);

private

   --  Private wrapper for internal hashing logic.
   --  @note Identical contracts from Public_Hash.
   --  @see Public_Hash
   procedure Hash (Item : in out Data)
     with Global  => (In_Out => (Ada.Text_IO.File_System,
                              Wrapper_ZeroMemory.Secure_Clean)),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                Wrapper_ZeroMemory.Secure_Clean =>
                  (Item, Wrapper_ZeroMemory.Secure_Clean),
                Ada.Text_IO.File_System =>+ (Item)),

     Pre     => Item.Password /= (Item.Password'Range => ASCII.NUL)
     and then (for all H of Item.Hash => H = '0')
     and then Item.Status /= 0,

     Post    => (for all P of Item.Password => P = '0')
     and then
       (if Item.Status = 0 then
          Is_Valid_Argon2_Format (Encoded_Hash => Item.Hash,
                                  Valid_Len    => Item.Hash_Length)
        else
          (for all C of Item.Hash => C = '0'));

   --========================================================================--

   --  Private wrapper for internal verification logic.
   --  @note Identical contracts from Public_Verify.
   --  @see Public_Verify
   procedure Verify (Item : in out Verify_Data)
     with Global  => (In_Out => (Ada.Text_IO.File_System,
                              Wrapper_ZeroMemory.Secure_Clean)),

     Depends => (Item => (Item, Wrapper_ZeroMemory.Secure_Clean),
                Wrapper_ZeroMemory.Secure_Clean =>
                  (Item, Wrapper_ZeroMemory.Secure_Clean),
                Ada.Text_IO.File_System =>+ (Item)),

     Pre     => Item.Password /= (Item.Password'Range => '0')
     and then Item.Hash /= (Item.Hash'Range => '0')
     and then Item.Same = False,

     Post    => (for all P of Item.Password => P = '0')
     and then (for all H of Item.Hash => H = '0')
     and then Item.Same = (Item.Status = 0)
     and then (if Item.Same then Item.Status = 0);

   E_Message   : constant String (1 .. 20) := "Exception Message : ";
   E_Name      : constant String (1 .. 20) := "Exception Name    : ";
   E_Providers : constant String (1 .. 24) := "Entropy providers failed";
   E_Format    : constant String (1 .. 20) := "Argon invalid format";
   Argon_Error : constant String (1 .. 20) := "Argon2 Error      : ";

   --  Computes and encodes an Argon2id password hash using the C library.
   --
   --  @param T_Cost      Time cost (number of iterations).
   --  @param M_Cost      Memory cost in kibibytes.
   --  @param Parallelism Degree of parallelism (threads/lanes).
   --  @param Pwd         Pointer to the password input buffer.
   --  @param Pwd_Len     Length in bytes of the password.
   --  @param Salt        Pointer to the cryptographic salt buffer.
   --  @param Salt_Len    Length in bytes of the salt.
   --  @param Hash_Len    Desired raw hash output length in bytes.
   --  @param Encoded     Pointer to the output encoded hash string buffer.
   --  @param Encoded_Len Maximum capacity of the encoded buffer.
   --  @return BOOL status code (0 for ARGON2_OK, error code otherwise).
   --
   --  @note Preconditions:
   --  - All major pointers (Pwd, Salt, Encoded) must be non-null.
   function Argon2id_Hash_Encoded
     (T_Cost      : Time_Cost_Range;
      M_Cost      : Memory_Cost_Range;
      Parallelism : T_Parallelism;
      Pwd         : POINTER;
      Pwd_Len     : Pswd_Length;
      Salt        : POINTER;
      Salt_Len    : Salt_Max_Bytes;
      Hash_Len    : Hash_Len_Bytes;
      Encoded     : POINTER;
      Encoded_Len : Real_Length_Valid)
      return BOOL
     with Import   => True,
     Convention    => C,
     External_Name => "argon2id_hash_encoded",
     Pre           => Pwd /= System.Null_Address
     and then Salt /= System.Null_Address
     and then Encoded /= System.Null_Address;

   --  Verifies a candidate password against an encoded Argon2id hash string.
   --
   --  @param Encoded Pointer to the null-terminated encoded hash string.
   --  @param Pwd     Pointer to the candidate password buffer.
   --  @param Pwd_Len Length in bytes of the candidate password.
   --  @return BOOL status code (0 for ARGON2_OK, error code otherwise).
   --
   --  @note Preconditions:
   --  - Pointers Encoded and Pwd must be non-null addresses.
   function Argon2id_Verify
     (Encoded : POINTER;
      Pwd     : POINTER;
      Pwd_Len : Pswd_Length)
      return BOOL
     with Import   => True,
     Convention    => C,
     External_Name => "argon2id_verify",
     Pre           => Encoded /= System.Null_Address
     and then Pwd /= System.Null_Address;

   subtype Type_Kind_Arg is Interfaces.C.int range 2 .. 2;

   --  Calculates the exact required length for an encoded Argon2 string.
   --
   --  @param T_Cost      Time cost (number of iterations).
   --  @param M_Cost      Memory cost in kibibytes.
   --  @param Parallelism Degree of parallelism.
   --  @param Salt_Len    Length of the salt in bytes.
   --  @param Hash_Len    Length of the raw hash in bytes.
   --  @param Type_Kind   Argon2 variant type kind (default is 2 for Argon2id).
   --  @return C_Size_T representing the required string buffer length.
   function Argon2_Encoded_Len
     (T_Cost      : Time_Cost_Range;
      M_Cost      : Memory_Cost_Range;
      Parallelism : T_Parallelism;
      Salt_Len    : Salt_Max_Bytes_U;
      Hash_Len    : Hash_Len_Bytes_U;
      Type_Kind   : Type_Kind_Arg := 2)
      return C_Size_T
     with Import   => True,
     Convention    => C,
     External_Name => "argon2_encodedlen";

end Argon2_Hash_Data;
