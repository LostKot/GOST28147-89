using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace GOST
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            //   Debug.Print(0b01110101.ToString());
            //  Debug.Print(ByteWork.OneCounter(UInt64.MaxValue).ToString());
           // Debug.Print(ByteWork.OneCounter(17475851676712937050 ^ 2375614654705427937).ToString());
        }

        public void Crypts(object sender, RoutedEventArgs e) 
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding win1251 = Encoding.GetEncoding("Windows-1251");
          //  byte[] temp = win1251.GetBytes("—€L\u0011G\u001dдШ");
            //ulong temp2 = (temp[0]<<24) | (temp[1] << 24);

            string Key = Key_Text.Text;
            int len = Key.Length;
            if (Key.Length !=32)
            {
                for (int i = 0; i < 32 - len; i++)
                {
                    Key += Key[i];

                }
                Debug.Print(Key);
            }
           // Debug.Print(Key);
            ulong[] shifr = GOST28147V2.Crypt(win1251.GetBytes(Key), win1251.GetBytes(In_Text.Text +'!'));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < shifr.Length; i++)
            {
                if (i == 0)
                {
                    sb.Append(shifr[i]);
                }
                else 
                {
                    sb.Append(" " + shifr[i]);
                }
                
            }
            Out_Text.Text = sb.ToString();
         

            
        }
        public void DeCrypts(object sender, RoutedEventArgs e)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding win1251 = Encoding.GetEncoding("Windows-1251");
            string[] cryptText = Out_Text.Text.Split(' ');
            ulong[] Text = new ulong[cryptText.Length];

            for (int i = 0; i < cryptText.Length; i++)
            {
                Text[i] = Convert.ToUInt64(cryptText[i]);
            }
            string Key = Key_Text.Text;
            int len = Key.Length;
            if (Key.Length != 32)
            {
                for (int i = 0; i < 32 - len; i++)
                {
                    Key += Key[i];
                }

            }
            ulong[] outText = GOST28147V2.DeCrypt(win1251.GetBytes(Key), Text);
            int temp = outText.Length;
            int StringlenghtToMeth = 0;
            for (int i = temp-1; i >= 0; i--)
            {
                if (outText[i] == 33)
                {
                    StringlenghtToMeth = i;
                    break;
                }
            }
            if (StringlenghtToMeth == 0)
            {
                StringlenghtToMeth = temp;
            }
          //  Debug.Print(outText.Length.ToString());
            byte[] OutTextToByte = new byte[StringlenghtToMeth];

            for (int i = 0; i < StringlenghtToMeth; i++)
            {
                OutTextToByte[i] = (byte) outText[i];
               // Debug.Print(OutTextToByte[i].ToString());
            }

            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < outText.Length; i++)
            {
             
                    sb.Append(outText[i]);
               
                
            }
            In_Text.Text = win1251.GetString(OutTextToByte);

       



        }
        public void Gen(object sender, RoutedEventArgs e)
        {
            Random r = new Random();
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding win1251 = Encoding.GetEncoding("Windows-1251");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                sb.Append(win1251.GetString(new byte[]{(byte)r.Next(33,256)}));
            }
            Key_Text.Text = sb.ToString();
        }

        private void OpenFile(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.DefaultExt = ".txt";
            dialog.Filter = "Text documents (.txt)|*.txt";

            bool? result = dialog.ShowDialog();

            if (result == true)
            {
                // Open document
                string filename = dialog.FileName;
                StreamReader sr = new StreamReader(filename);
                string line = sr.ReadLine();
                StringBuilder sb = new StringBuilder();
                // Maintext = File.ReadAllText(filename);
                while (line != null)
                {
                    sb.Append(line);

                    line = sr.ReadLine();
                }
                In_Text.Text = sb.ToString();
            }
      }

       
    }
}
