using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST
{
    internal static class GOST28147V2
    {
        private static ulong[,] Sbox =
        {
            {4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3 },
            {14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9 },
            {5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11 },
            {7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3 },
            {6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2 },
            {4,11,10,0,7,2,1,13,3,6 ,8,5,9,12,15,14 },
            {13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12 },
            {1,15,13,0,5,7,10,4,9,2 ,3,14,6,11,8,12 }
        };

        public static ulong[] Crypt(byte[] key, byte[] text) 
        {
            ulong[] keys = new ulong[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                keys[i] = key[i];
            }
            ulong[] keyBlock = GetKeysMass(keys);//Получаем 32 битные ключи
            
            ulong[] N = GetNBlocks(text);
            int lenght = N.Length;
           // Debug.Print(N[0].ToString());
            ulong[] Shifr = new ulong[lenght];
            for (int i = 0; i < lenght; i++)
            {
              //  N = GetNBlocks(text[i]);
               Shifr[i] = fiestel_crypt(keyBlock,new ulong[] { (N[i] >>32) & UInt32.MaxValue, N[i] & UInt32.MaxValue });
            }
            
            return Shifr;

        }
        public static ulong[] DeCrypt(byte[] key, ulong[] text)
        {
            ulong[] keys = new ulong[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                keys[i] = key[i];
            }
            ulong[] keyBlock = GetKeysMass(keys);//Получаем 32 битные ключи
            int lenght = text.Length;
          //  ulong[] N;
            ulong[] textOut = new ulong[lenght*8];
            ulong temp = 0;
            for (int i = 0; i < lenght; i++)
            {
                //  N = GetNBlocks(text[i]);
                temp = fiestel_Decrypt(keyBlock, new ulong[] { (text[i] >> 32), text[i] & UInt32.MaxValue });//0b11111111111111111111111111111111


                for (int j = 0; j < 8; j++)
                {
                    textOut[i * 8 +j] = (temp >> 56 - 8*j) & 255;
                }
     

            }
         //   Debug.Print(temp.ToString());
            return textOut;

        }
        public static ulong[] GetKeysMass(ulong[] key) 
        {
            ulong[] keys = new ulong[8];

            for (int i = 0; i < 8; i++)
            {
                keys[i] = (key[i*4] << 24) | (key[i * 4 +1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
            }

            return keys;
        }

        public static ulong[] GetNBlocks(byte[] symbol) 
        {
            ulong[] N;
            ulong[] symbolUint;
            if (symbol.Length % 8 != 0)
            {
                long len = symbol.Length; // + (8 - (symbol.Length % 8));
                symbolUint = new ulong[len + (8-(len % 8))];
                long len2 = len + (8 - (len % 8));
                N = new ulong[len2 / 8];
                Random rand = new Random();
                for (long i = 0; i < len; i++)
                {
                    symbolUint[i] = symbol[i];
                }
                for (long i = len; i < len2; i++)
                {
                    symbolUint[i] = Convert.ToUInt64(rand.Next(34, 256));
                }
            }
            else
            {
                long len = symbol.Length;
                N = new ulong[len/8];
                symbolUint = new ulong[len];
                for (long i = 0; i < len; i++)
                {
                    symbolUint[i] = symbol[i];
                }
            }
            long len3 = N.Length; 
            for (int i = 0; i < len3; i++)
            {
                N[i] = (symbolUint[i*8] << 56) | (symbolUint[i * 8 + 1] << 48) | (symbolUint[i * 8 + 2] << 40) | (symbolUint[i * 8 + 3] << 32) | (symbolUint[i * 8 + 4] << 24) | (symbolUint[i * 8 + 5] << 16) | (symbolUint[i * 8 + 6] << 8) | (symbolUint[i * 8 + 7]);
                //Debug.Print(N[i].ToString());
            }
            return N;
           


        }

        private static ulong[] GetNBlocks(ulong symbol)
        {
            // ulong symboluint = symbol;
            ulong N1 = symbol >>32;
            ulong N2 = symbol & UInt32.MaxValue;
            return new ulong[] { N1, N2 };
        }

        private static ulong fiestel_crypt(ulong[] keyBlock, ulong[] N) 
        {
            ulong N1 = N[0];
            ulong N2 = N[1];
            ulong w = 0;
            int j = 0;


            while (j <3)
            {
                for (int i = 0; i < 8; i++)
                {
                    w = (N1 + keyBlock[i]) & UInt32.MaxValue;
                    w = SboxSwitch(w);
                    w = CycleShift11(w) ^ N2;
                    N2 = N1;
                    N1 = w;
                }
                j++;
            }
            
            for (int i = 7; i > 0; i--)
            {
                w = (N1 + keyBlock[i]) & UInt32.MaxValue;
                w = SboxSwitch(w);
                w = CycleShift11(w) ^ N2;
                N2 = N1;
                N1 = w;
            }

            w = (N1 + keyBlock[0]) & UInt32.MaxValue;
            w = SboxSwitch(w);
            w = CycleShift11(w) ^ N2;
            N2 = w;

            return (N1 <<32) | N2;
        }
        private static ulong fiestel_Decrypt(ulong[] keyBlock, ulong[] N)
        {
            ulong N1 = N[0];
            ulong N2 = N[1];
            ulong w = 0;
            int j = 0;
            for (int i = 0; i < 8; i++)
            {
                w = (N1 + keyBlock[i]) & UInt32.MaxValue;
                w = SboxSwitch(w);
                w = CycleShift11(w) ^ N2;
                N2 = N1;
                N1 = w;
            }
      
            while (j < 2)
            {
                for (int i = 7; i >= 0; i--)
                {
                    w = (N1 + keyBlock[i]) & UInt32.MaxValue;
                    w = SboxSwitch(w);
                    w = CycleShift11(w) ^ N2;
                    N2 = N1;
                    N1 = w;
                }
                j++;
            }

            for (int i = 7; i > 0; i--)
            {
                w = (N1 + keyBlock[i]) & UInt32.MaxValue;
                w = SboxSwitch(w);
                w = CycleShift11(w) ^ N2;
                N2 = N1;
                N1 = w;
            }

            w = (N1 + keyBlock[0]) & UInt32.MaxValue;
            w = SboxSwitch(w);
            w = CycleShift11(w) ^ N2;
            N2 = w;
           //   Debug.Print(((N1 << 32 )| N2).ToString());
            return (N1 << 32) | N2;
        }

        private static ulong SboxSwitch(ulong w) 
        {
            ulong[] bits4 = new ulong[8];
            ulong outs = 0;
            ulong mask = 0b1111;
            bits4[0] = w >> 28;
            bits4[1] = w >> 24 & mask;
            bits4[2] = w >> 20 & mask;
            bits4[3] = w >> 16 & mask;
            bits4[4] = w >> 12 & mask;
            bits4[5] = w >> 8 & mask;
            bits4[6] = w >> 4 & mask;
            bits4[7] = w & mask;


            for (int i = 0; i < 8; i++)
            {
                bits4[i] = Sbox[i, bits4[i]];
            }

            outs = (bits4[0] << 28) | (bits4[1] <<24) | (bits4[2] << 20) | (bits4[3] << 16) | (bits4[4] << 12) | (bits4[5] << 8) | (bits4[6] << 4) | bits4[7];

            return outs;

        }

        private static ulong CycleShift11(ulong InBlock)
        {
            ulong temp = InBlock >> 21;
          
            return ((InBlock << 11) | temp) & UInt32.MaxValue;
        }


    }
}
