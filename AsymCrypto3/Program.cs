using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Globalization;


namespace AsymCrypto3 {
    class Program {

        public static string ReadLine() {
            System.IO.Stream inputStream = Console.OpenStandardInput(2048);
            byte[] bytes = new byte[2048];
            int outputLength = inputStream.Read(bytes, 0, 2048);
            //Console.WriteLine(outputLength);
            char[] chars = Encoding.UTF7.GetChars(bytes, 0, outputLength);
            return new string(chars);
        }

        static void Main(string[] args) {

            ZeroKnowlegeProtocol.Attack();
            Users Alice = new Users();
            Alice.Interact();
        }
    }

    class Users {
    
        private BigInteger[] pqb;
        private string message;
        public BigInteger n, b;
        public BigInteger[] CT;
        public string signedmessage;
        public BigInteger Signature;

        public Users () { 
        
            this.pqb = null;
            this.message = "";
            this.n = 0;
            this.b = 0;
            this.CT = null;
        }

        public Users(string p, string q, string b) {

            this.pqb[0] = BigInteger.Parse(p, NumberStyles.HexNumber);
            this.pqb[1] = BigInteger.Parse(q, NumberStyles.HexNumber);
            this.pqb[2] = BigInteger.Parse(b, NumberStyles.HexNumber);
            this.message = "";
            this.n = this.pqb[0] * this.pqb[1];
            this.b = pqb[2];
            this.CT = null;
        }

        public Users(string n) {
        
            n = "0" + n;
            this.n = BigInteger.Parse(n, NumberStyles.HexNumber);
        }

        public void GenKeys () {

            this.pqb = RabinSystem.PrimeIntegrsGenerator();
            this.n = pqb[0] * pqb[1];
        }

        public void SendPublicKeyTo (Users user) {

            user.n = this.n;
            user.b = this.pqb[2];
        }

        public void SendMessageTo(Users user, string message) {
        
            user.SendPublicKeyTo(this);
            user.CT = RabinSystem.Encrypt(message, this.n, this.b);
        }

        public void ReadMessage () {
            
            this.message = RabinSystem.Decrypt(this.CT, this.pqb);
        }

        public void Sign (string message) {
        
            BigInteger[] s = RabinSystem.Signature(message, this.pqb);
            this.signedmessage = message;
            this.Signature = s[0];
            this.n = s[1];
        }

        public void Interact () {
        
            Console.WriteLine("Hi! I'm Alice.");

            while (true) {

                Console.WriteLine("\nWhat do you want me to do?\n"); 
                Console.WriteLine("1. Generate private key and publish public key, then decipher a message.");
                Console.WriteLine("2. Get public key and encrypt a message.");
                Console.WriteLine("3. Generate private key and publish public key, then sign a message.");
                Console.WriteLine("4. Get message and public key, then verify the signature.");
                Console.WriteLine("0. Exit.\n");
                Console.Write("Your choice is: ");
                
                string choice = Console.ReadLine();

                while(choice.Length != 1) {
                
                    Console.WriteLine("Wrong choice! Try again:");
                    choice = Console.ReadLine();
                }

                switch (choice) { 
                
                    case "1":

                        this.GenKeys();
                        Console.WriteLine("\n\n p = " + this.pqb[0].ToString("X") + "\n\n q = " + this.pqb[1].ToString("X"));
                        Console.WriteLine("n = {0}", this.n.ToString("X"));
                        Console.WriteLine("b = {0}", this.pqb[2].ToString("X"));
                        Console.WriteLine();
                        this.CT = new BigInteger[3];
                        Console.WriteLine("Ciphertext: ");
                        this.CT[0] = BigInteger.Parse("0"+Program.ReadLine(), NumberStyles.HexNumber);
                        Console.WriteLine("Parity: ");
                        this.CT[1] = BigInteger.Parse(Console.ReadLine());
                        Console.WriteLine("Jacobi Symbol: ");
                        this.CT[2] = BigInteger.Parse(Console.ReadLine());
                        this.message = RabinSystem.Decrypt(this.CT, this.pqb);
                        Console.WriteLine("\nMessage is: {0}", this.message);
                        break;

                    case "2":

                        Console.WriteLine("n = ");
                        this.n = BigInteger.Parse("0" + Program.ReadLine(), NumberStyles.HexNumber);
                        Console.WriteLine("b = ");
                        this.b = BigInteger.Parse("0" + Program.ReadLine(), NumberStyles.HexNumber);
                        this.CT = RabinSystem.Encrypt("Yare, yare daze", this.n, this.b);
                        Console.WriteLine("Encrypted message is: {0}\nRarity is: {1}\nJacobi Symbol is:{2}", this.CT[0].ToString("X"), this.CT[1], this.CT[2]);
                        break;

                    case "3":

                        this.GenKeys();
                        Console.Write("\nSigned message is: ");
                        string message = Console.ReadLine();                        
                        BigInteger[] sign = RabinSystem.Signature(message, this.pqb);
                        Console.WriteLine("\nSign is: {0}\n\nModulo is: {1}", sign[0].ToString("X"), sign[1].ToString("X"));
                        break;

                    case "4": 

                        Console.Write("\nMessage to verify is: ");
                        string signedmessage = Console.ReadLine();
                        Console.Write("\nIts signarute: ");
                        string signarute = Program.ReadLine();
                        Console.Write("\nIts modulo: ");
                        string n = Program.ReadLine();
                        Console.WriteLine("\nSignature is: " + RabinSystem.Verify(signedmessage, signarute, n));
                        break;

                    case "0": 
                        return;                     
                }
            }
        }
    }

//----------------------------------------------------------------------------------------------------|
    class RabinSystem {

        static private int keyLenght = 128;
        static private int accuracy = 100;
//----------------------------------------------------------------------------------------------------|
    
        public static BigInteger[] Encrypt (string message, BigInteger n, BigInteger b) {

            BigInteger x = Formatting(message, n);
            BigInteger y = BigInteger.Remainder(x*(x+b), n);

            x += b*modInverse(2, n);
            BigInteger c1 = BigInteger.Remainder(x, n)&1;
            BigInteger c2 = 0;
            if (Jacobi(x,n) == 1) c2 = 1;

            return new BigInteger[] {y, c1, c2};
        }
//----------------------------------------------------------------------------------------------------|
    
        public static string Decrypt (BigInteger[] CT, BigInteger[] pqb) {

            BigInteger p = pqb[0];
            BigInteger q = pqb[1];

            BigInteger y = CT[0];
            BigInteger c1 = CT[1];
            BigInteger c2 = CT[2];

            BigInteger n = p * q;

            y += BigInteger.Remainder(BigInteger.Pow(pqb[2], 2) * modInverse(4, n), n);

            BigInteger[] roots = BlumSqrt(y, p, q);

            BigInteger x = 0;

            for (int i = 0; i < 4; i++) {

                if ((roots[i] & 1) == c1) {

                    int ctemp;
                    if (Jacobi(roots[i], n) == 1) ctemp = 1;
                    else ctemp = 0;

                    if (ctemp == c2) {

                        x = roots[i];
                        break;
                    }
                }
            }

            x -= BigInteger.Remainder(pqb[2] * modInverse(2, n), n); 

            //if(x < 0) x += n;

            x = UnFormat(x, n);

            string message = BigIntToStr(x);

            return message;
        }
//----------------------------------------------------------------------------------------------------|

        public static BigInteger[] Signature (string message, BigInteger[] pq) {

            BigInteger n = pq[0] * pq[1];
            BigInteger x = Formatting(message, n);

            while((Jacobi(x, pq[0]) != 1) || (Jacobi(x, pq[0]) != 1)) 
                x = Formatting(message, n);

            BigInteger[] roots = BlumSqrt(x, pq[0], pq[1]);

            Random rand = new Random();
            int r = rand.Next(4);

            return new BigInteger[]{roots[r], n};
        }
//----------------------------------------------------------------------------------------------------|
    
        public static bool Verify (string message, string signature, string n) { 
        
            signature = "0" + signature;
            n = "0" + n;
            BigInteger s = BigInteger.Parse(signature, NumberStyles.HexNumber);
            BigInteger mod = BigInteger.Parse(n, NumberStyles.HexNumber);

            BigInteger m = StrToBigInt(message);
            BigInteger x = BigInteger.ModPow(s, 2, mod);

            x = UnFormat(x, mod);
            
            if (x == m) return true;

            return false;
        }
//----------------------------------------------------------------------------------------------------|

        public static BigInteger[] PrimeIntegrsGenerator () {
        
            BigInteger p = BBS_Generator();
            int pk = 0;
            int qk = 0;

            while (MillerRabinBlumTest(p) == false) { 
                p = BBS_Generator();
                pk++;    
            }

            Console.WriteLine(pk);

            BigInteger q = BBS_Generator();

            while (MillerRabinBlumTest(q) == false) { 
                q = BBS_Generator();
                qk++;
            }

            Console.WriteLine(qk);

            BigInteger b = RandomBigInteger(p*q - 1);

            return new BigInteger[]{p, q, b};
        }
//----------------------------------------------------------------------------------------------------|

        private static bool MillerRabinBlumTest(BigInteger p) {
        
            BigInteger watch = (p-3)%4;
            
            int k = accuracy;

            int s = 0;
            BigInteger d = p - 1;

            while (d.IsEven) {
                
                d >>= 1; ;
                s++;
            }

            for (int i = 0; i < k; i++) {

                BigInteger x = RandomBigInteger(p);
                if (BigInteger.GreatestCommonDivisor(x, p) > 1)
                    return false;
                BigInteger xr = BigInteger.ModPow(x, d, p);
                if((xr == 1)||(xr == p-1))
                    continue;
                
                int r = 1;

                for (; r < s; r++) {

                    xr = (xr * xr) % p;
                    if (xr == p-1) break;
                    if (xr == 1) return false;

                }

                if (r == s) return false;
            }

            return true;
        }
//----------------------------------------------------------------------------------------------------|
        
        private static BigInteger BBS_Generator() {

            BigInteger p = BigInteger.Parse("0D5BBB96D30086EC484EBA3D7F9CAEB07", NumberStyles.HexNumber);
            BigInteger q = BigInteger.Parse("425D2B9BFDB25B9CF6C416CC6E37B59C1F", NumberStyles.HexNumber);
            BigInteger n = p * q;

            BigInteger r = RandomBigInteger(n-1);

            byte[] bytes = new byte[keyLenght + 1];

            for (int i = 0; i < bytes.Length - 1; i++) {

                r = BigInteger.ModPow(r, 2, n);
                bytes[i] = (byte)((0b11111111) & r);
            }

            bytes[keyLenght-1]|= 0b10000000;

            return (new BigInteger(bytes))|3;
        }
//----------------------------------------------------------------------------------------------------| function's taken from https://cswiki.cs.byu.edu/cs-312/randombigintegers

        private static BigInteger Jacobi(BigInteger x, BigInteger n) {
        
            if (BigInteger.Remainder(x, n) == 0) return 0;

            int result = 1;

            while (x.IsOne == false) {

                if (x == 0) return 0;

                int ind = 0;
                while (x.IsEven) {

                    x >>= 1;
                    ind++;
                }

                if ((ind&1) == 1) if(((BigInteger.Pow(n, 2)-1)/8).IsEven == false) result*=-1;

                if (x.IsOne) break;

                if (((n-1)*(x - 1)/ 4).IsEven == false) result *= -1;

                BigInteger temp = x;
                x = BigInteger.Remainder(n, x);
                n = temp;

            }
            
            return x*result;
        }
//----------------------------------------------------------------------------------------------------| 

        private static BigInteger Formatting(string message, BigInteger n) {

            string number = n.ToString("X");
            int l = number.Length;
            if(number[0] == '0') l/=2;
            else l = (l+1)/2;

            BigInteger m = StrToBigInt(message);
            BigInteger r = RandomBigInteger(BigInteger.Pow(2,64));

            BigInteger x = m*(BigInteger.Pow(2, 64)) + r;

            x += 255 * BigInteger.Pow(2, 8*(l-2));

            return x;
        } 
//----------------------------------------------------------------------------------------------------| 

        private static BigInteger UnFormat (BigInteger x, BigInteger n) {

            string number = n.ToString("X");
            int l = number.Length;
            if (number[0] == '0') l /= 2;
            else l = (l + 1) / 2;

            x = BigInteger.Remainder(x, BigInteger.Pow(2, 8 * (l - 2)));

            x >>= 64;

            return x;
        }
//----------------------------------------------------------------------------------------------------|

        public static BigInteger RandomBigInteger(BigInteger N) {

            Random rand = new Random();

            BigInteger result = 0;
            do {
                int length = (int)Math.Ceiling(BigInteger.Log(N, 2));
                int numBytes = (int)Math.Ceiling(length / 8.0);
                byte[] data = new byte[numBytes];
                rand.NextBytes(data);
                result = new BigInteger(data);
            } while (result >= N || result <= 0);
            return result;
        }
//----------------------------------------------------------------------------------------------------| 

        static BigInteger[] BlumSqrt (BigInteger y, BigInteger p, BigInteger q) {
        
            BigInteger s1 = BigInteger.ModPow(y, (p+1) >> 2, p);
            BigInteger s2 = BigInteger.ModPow(y, (q+1) >> 2, q);

            BigInteger n = p * q;

            BigInteger[] uv = egcd(p, q);

            BigInteger u = uv[1];
            BigInteger v = uv[2];

            BigInteger[] result = new BigInteger[4];

            result[0] = u * p * s2 + v * q * s1;            
            if (result[0] < 0) {

                result[0] *= -1;
                result[0] %=n;
                result[0] = n - result[0];
            }
            else result[0]%=n;
            result[1] = n - result[0];
            result[2] = u * p * s2 - v * q * s1;
            if (result[2] < 0) {

                result[2] *= -1;
                result[2] %= n;
                result[2] = n - result[2];
            }
            else result[2]%=n;
            result[3] = n - result[2];

            return result;
        } 
//----------------------------------------------------------------------------------------------------| 

       public static BigInteger[] egcd (BigInteger a, BigInteger b) {

            if (a == 0) 
                return new BigInteger[] { b, 0, 1};

            BigInteger[] res = egcd(b%a, a);
            BigInteger x = res[2] - (b/a)*res[1];
            BigInteger y = res[1];
            return new BigInteger[] { res[0], x, y};
        }
//----------------------------------------------------------------------------------------------------| 

        public static BigInteger modInverse(BigInteger a, BigInteger n) {

            BigInteger i = n, v = 0, d = 1;
            while (a > 0) {

                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
//----------------------------------------------------------------------------------------------------| 

        static string BigIntToStr(BigInteger x) {

            string number = x.ToString("X");
            if ((number.Length % 2) == 1) number = "0" + number;

            byte[] bytes = new byte[number.Length/2];

            for (int i = 0; i < bytes.Length; i ++) {

                bytes[i] = Convert.ToByte(number.Substring(i*2, 2), 16);
            }

            return Encoding.ASCII.GetString(bytes);
        }
//----------------------------------------------------------------------------------------------------| 

        static BigInteger StrToBigInt(string message) {

            byte[] bytes = new byte[message.Length];

            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(message[message.Length - 1 - i]);

            return new BigInteger(bytes);
        }
    }
//----------------------------------------------------------------------------------------------------|

    class ZeroKnowlegeProtocol {
    
        public static void Attack (){
        
            Console.Write("n = ");
            BigInteger n = BigInteger.Parse("0" + Program.ReadLine(), NumberStyles.HexNumber);
            int number_of_tries = 0;

            while(true) {
            
                number_of_tries++;
                BigInteger t = RabinSystem.RandomBigInteger(n);
                BigInteger y = BigInteger.ModPow(t, 2, n);
                Console.WriteLine("\ny = " + y.ToString("X"));
                Console.Write("\nz = ");
                BigInteger z = BigInteger.Parse("0" + Program.ReadLine(), NumberStyles.HexNumber);
                if((t== z) || (t == (n-z))) {
                    Console.WriteLine("\nDidn't work! I'm trying again...");
                    continue;
                }
                else {
                    BigInteger p = RabinSystem.egcd(t + z, n)[0];
                    BigInteger q = n / p;
                    if (p * q == n) {
                        Console.WriteLine("\nVictory!\n\np = {0}\nq = {1}\n\nNumber of tries: {2}", p.ToString("X"), q.ToString("X"), number_of_tries);
                        Console.ReadLine();
                        return;
                    }
                    else { 
                        Console.WriteLine("Something went wrong!");
                        continue;
                    }
                }
            }
        }
    }
}
