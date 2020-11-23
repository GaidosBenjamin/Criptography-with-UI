using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using Microsoft.Win32;
using System.Security.Cryptography;
using System.IO;

namespace WpfApp1
{
   
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string algorithm = this.AlgorithmComboBox.Text;
            string cipher = this.CipherComboBox.Text;
            string padding = this.PaddingComboBox.Text;
            string key = this.KeyTextBox.Text;
            if (key == null)
                throw new ArgumentNullException("Key is null");
            chooseAlgorithmDecryption(algorithm, cipher, padding, key);
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string algorithm = this.AlgorithmComboBox.Text;
            string cipher = this.CipherComboBox.Text;
            string padding = this.PaddingComboBox.Text;
            string key = this.KeyTextBox.Text;
            if (key == null)
                throw new ArgumentNullException("Key is null");
            chooseAlgorithmEncryption(algorithm, cipher, padding, key);
        }

        private void CustomKeyButton_Click(object sender, RoutedEventArgs e)
        {
            InputKey inputKey = new InputKey();
            if (inputKey.ShowDialog() == true)
                this.KeyTextBox.Text = inputKey.Answer;
        }

        private void RandomKeyButton_Click(object sender, RoutedEventArgs e)
        {
            Random rnd = new Random();
            
            switch (this.AlgorithmComboBox.Text)
            {
                case "Aes":
                    byte[] key = new byte[32];
                    rnd.NextBytes(key);
                    this.KeyTextBox.Text = getString(key);
                    break;
                case "DES":
                    byte[] keyDes = new byte[8];
                    rnd.NextBytes(keyDes);
                    this.KeyTextBox.Text = getString(keyDes);
                    break;
                case "TripleDES":
                    byte[] keyTripleDes = new byte[16];
                    rnd.NextBytes(keyTripleDes);
                    this.KeyTextBox.Text = getString(keyTripleDes);
                    break;
                case "RC2":
                    byte[] keyRC2 = new byte[16];
                    rnd.NextBytes(keyRC2);
                    this.KeyTextBox.Text = getString(keyRC2);
                    break;
                case "Rijndael":
                    byte[] keyRijandel = new byte[32];
                    rnd.NextBytes(keyRijandel);
                    this.KeyTextBox.Text = getString(keyRijandel);
                    break;
            }
        }

        private void InputChooseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.DefaultExt = ".txt"; // Default file extension
            fileDialog.Filter = "Text documents (.txt)|*.txt"; // Filter files by extension

            Nullable<bool> result = fileDialog.ShowDialog();

            if (result == true)
            {
                string filename = fileDialog.FileName;
                this.InputTextBox.Text = filename;
            }
        }

        private void OutputChooseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.DefaultExt = ".txt"; // Default file extension
            fileDialog.Filter = "Text documents (.txt)|*.txt"; // Filter files by extension

            Nullable<bool> result = fileDialog.ShowDialog();

            if (result == true)
            {
                string filename = fileDialog.FileName;
                this.OutputTextBox.Text = filename;
            }
        }

        private byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        private string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        private void AlgorithmComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (this.KeyTextBox == null)
                return;
            this.KeyTextBox.Text = "After reselecting algorithm key must be remade";
        }

        private void chooseAlgorithmEncryption(String algorithm, String cipher, String padding, String key)
        {
            switch(algorithm)
            {
                case "Aes":
                    aesEncryption(cipher, padding, key);
                    break;
                case "DES":
                    desEncryption(cipher, padding, key);
                    break;
                case "TripleDES":
                    tripleDesEncryption(cipher, padding, key);
                    break;
                case "RC2":
                    rc2Encryption(cipher, padding, key);
                    break;
                case "Rijndael":
                    rijndaelEncryption(cipher, padding, key);
                    break;
            }
        }

        private void chooseAlgorithmDecryption(String algorithm, String cipher, String padding, String key)
        {
            switch (algorithm)
            {
                case "Aes":
                    aesDecryption(cipher, padding, key);
                    break;
                case "DES":
                    desDecryption(cipher, padding, key);
                    break;
                case "TripleDES":
                    tripleDesDecryption(cipher, padding, key);
                    break;
                case "RC2":
                    rc2Decryption(cipher, padding, key);
                    break;
                case "Rijndael":
                    rijndaelDecryption(cipher, padding, key);
                    break;
            }
        }

        private void aesEncryption(String cipher, String padding, String key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                aes.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                aes.KeySize = 256;
                aes.Key = getBytes(this.KeyTextBox.Text);                 

                string input = File.ReadAllText(this.InputTextBox.Text);

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                File.WriteAllBytes(this.OutputTextBox.Text, encrypted);
                MessageBox.Show("Succesfuly encrypted!");
            }
        }

        private void aesDecryption(String cipher, String padding, String key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                aes.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                aes.KeySize = 256;
                aes.Key = getBytes(this.KeyTextBox.Text);

                byte[] input = File.ReadAllBytes(this.InputTextBox.Text);
                string output = null;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            output = srDecrypt.ReadToEnd();
                        }
                    }
                }

                File.WriteAllText(this.OutputTextBox.Text, output);
                MessageBox.Show("Succesfuly decrypted!");
            }
        }

        private void desEncryption(String cipher, String padding, String key)
        {
            using (DES des = DES.Create())
            {
                des.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                des.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                des.KeySize = 64;
                des.Key = getBytes(this.KeyTextBox.Text);

                string input = File.ReadAllText(this.InputTextBox.Text);

                ICryptoTransform encryptor = des.CreateEncryptor(des.Key, des.IV);
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                File.WriteAllBytes(this.OutputTextBox.Text, encrypted);
                MessageBox.Show("Succesfuly encrypted!");
            }
        }
    

        private void desDecryption(String cipher, String padding, String key)
        {
            using (DES des = DES.Create())
            {
                des.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                des.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                des.KeySize = 64;
                des.Key = getBytes(this.KeyTextBox.Text);

                byte[] input = File.ReadAllBytes(this.InputTextBox.Text);
                string output = null;

                ICryptoTransform decryptor = des.CreateDecryptor(des.Key, des.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            output = srDecrypt.ReadToEnd();
                        }
                    }
                }

                File.WriteAllText(this.OutputTextBox.Text, output);
                MessageBox.Show("Succesfuly decrypted!");
            }
        }

        private void rc2Encryption(String cipher, String padding, String key)
        {
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                rc2.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                rc2.KeySize = 128;
                rc2.Key = getBytes(this.KeyTextBox.Text);

                string input = File.ReadAllText(this.InputTextBox.Text);

                ICryptoTransform encryptor = rc2.CreateEncryptor(rc2.Key, rc2.IV);
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                File.WriteAllBytes(this.OutputTextBox.Text, encrypted);
                MessageBox.Show("Succesfuly encrypted!");
            }
        }

        private void rc2Decryption(String cipher, String padding, String key)
        {
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                rc2.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                rc2.KeySize = 128;
                rc2.Key = getBytes(this.KeyTextBox.Text);

                byte[] input = File.ReadAllBytes(this.InputTextBox.Text);
                string output = null;

                ICryptoTransform decryptor = rc2.CreateDecryptor(rc2.Key, rc2.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            output = srDecrypt.ReadToEnd();
                        }
                    }
                }

                File.WriteAllText(this.OutputTextBox.Text, output);
                MessageBox.Show("Succesfuly decrypted!");
            }
        }

        private void tripleDesEncryption(String cipher, String padding, String key)
        {
            using (TripleDES tDes = TripleDES.Create())
            {
                tDes.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                tDes.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                tDes.KeySize = 128;
                tDes.Key = getBytes(this.KeyTextBox.Text);

                string input = File.ReadAllText(this.InputTextBox.Text);

                ICryptoTransform encryptor = tDes.CreateEncryptor(tDes.Key, tDes.IV);
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                File.WriteAllBytes(this.OutputTextBox.Text, encrypted);
                MessageBox.Show("Succesfuly encrypted!");
            }
        }

        private void tripleDesDecryption(String cipher, String padding, String key)
        {
            using (TripleDES tDes = TripleDES.Create())
            {
                tDes.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                tDes.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                tDes.KeySize = 128;
                tDes.Key = getBytes(this.KeyTextBox.Text);

                byte[] input = File.ReadAllBytes(this.InputTextBox.Text);
                string output = null;

                ICryptoTransform decryptor = tDes.CreateDecryptor(tDes.Key, tDes.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            output = srDecrypt.ReadToEnd();
                        }
                    }
                }

                File.WriteAllText(this.OutputTextBox.Text, output);
                MessageBox.Show("Succesfuly decrypted!");
            }
        }

        private void rijndaelEncryption(String cipher, String padding, String key)
        {
            using (Rijndael rijandael = Rijndael.Create())
            {
                rijandael.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                rijandael.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                rijandael.KeySize = 256;
                rijandael.Key = getBytes(this.KeyTextBox.Text);

                string input = File.ReadAllText(this.InputTextBox.Text);

                ICryptoTransform encryptor = rijandael.CreateEncryptor(rijandael.Key, rijandael.IV);
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                File.WriteAllBytes(this.OutputTextBox.Text, encrypted);
                MessageBox.Show("Succesfuly encrypted!");
            }
        }

        private void rijndaelDecryption(String cipher, String padding, String key)
        {
            using (Rijndael rijndael = Rijndael.Create())
            {
                rijndael.Mode = (CipherMode)Enum.Parse(typeof(CipherMode), cipher, true);
                rijndael.Padding = (PaddingMode)Enum.Parse(typeof(PaddingMode), padding, true);
                rijndael.KeySize = 256;
                rijndael.Key = getBytes(this.KeyTextBox.Text);

                byte[] input = File.ReadAllBytes(this.InputTextBox.Text);
                string output = null;

                ICryptoTransform decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

                using (MemoryStream msDecrypt = new MemoryStream(input))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            output = srDecrypt.ReadToEnd();
                        }
                    }
                }

                File.WriteAllText(this.OutputTextBox.Text, output);
                MessageBox.Show("Succesfuly decrypted!");
            }
        }

    }
}
