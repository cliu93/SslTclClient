using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SslTcpClient
{
    public partial class SslTcpClient : Form
    {
        public int debug = 0;       //Disable debug, please set the value to 0
        //public int debug = 1;     //Enable debug to capture sslv2ClientHello and sslv2ServerHello
        //public int debug = 2;     //Enable debug to capture error when parse sslv2ServerHello stream
        //public int debug = 3;     //Enable debug to capture sslv2ClientHello and sslv2ServerHello


        public byte[] unknowCipherSuite = { 0xFF, 0xFF };

        public SslTcpClient()
        {
            InitializeComponent();
        }

        private void SslTcpClient_Load(object sender, EventArgs e)
        {
            txtOutPut.Clear();
            txtServerUrl.Text = "";
            txtProtocol.Text = "TLSv10";
            txtServerPort.Text = "443";
            checkBoxQuickTest.Checked = false;
            btnScan.Enabled = true;
            txtProtocol.Enabled = false;
            txtCipher.Enabled = false;
        }

        //btnReset_Click() is used for Reset button
        private void btnReset_Click(object sender, EventArgs e)
        {
            txtOutPut.Clear();
            checkBoxQuickTest.Checked = false;
            btnScan.Enabled = true;
            txtProtocol.Enabled = false;
            txtCipher.Enabled = false;
        }

        //ListAllCiphers() is used for List button
        private void ListAllCiphers(object sender, EventArgs e)
        {
            string cipherSuitesHex;
            foreach (TLSCipherSuite cipherSuites in (TLSCipherSuite[])Enum.GetValues(typeof(TLSCipherSuite)))
            {
                cipherSuitesHex = String.Format("{0:X4}", (Int16)cipherSuites);
                txtOutPut.AppendText("Cipher: " + cipherSuites + "    0x" + cipherSuitesHex + Environment.NewLine);
            }
        }

        //btnConnect_Click() is used for Connect button
        private void btnConnect_Click(object sender, EventArgs e)
        {
            UInt16 port;
            if ( !UInt16.TryParse(txtServerPort.Text, out port) )
            {
                txtOutPut.AppendText("The port number is invalid. Please check." + Environment.NewLine);
                return;
            }

            string server = txtServerUrl.Text;
            var regexServer = @"^(([a-z_A-Z0-9]|[a-z_A-Z0-9][a-z_A-Z0-9\-]*[a-z_A-Z0-9])\.)*([A-Z_a-z0-9]|[A-Z_a-z0-9][A-Z_a-z0-9\-]*[A-Z_a-z0-9])$";
            var matchServer = Regex.Match(server, regexServer);
            if (!matchServer.Success)
            {
                txtOutPut.AppendText("The server url is invalid." + Environment.NewLine);
                return;
            }

            try
            {
                TcpClient tcpClient = new TcpClient(server, port);
                tcpClient.Close();
            }
            catch (Exception econnectionException)
            {
                txtOutPut.AppendText("Failed to connect to server: " + server + ":" + port + Environment.NewLine);
                txtOutPut.AppendText(econnectionException.Message + Environment.NewLine);
                return;
            }      
            
            if (txtProtocol.Text == "SSLv20")
            {
                sslv2connect(server, port);
                return;
            }

            string cipher = txtCipher.Text;
            cipher = cipher.ToUpper();
            cipher = cipher.Replace(" ", "");
            cipher = cipher.Replace(",", "");
            cipher = cipher.Replace("0X", "");

            var regexCipher = @"[A-F0-9][A-F0-9][A-F0-9][A-F0-9]";
            var matchCipher = Regex.Match(cipher, regexCipher);
            if (!matchCipher.Success)
            {
                txtOutPut.AppendText("The Cipher is invalid, it should be 2 byte integer in hex format like 0x0000, 0xD005." + Environment.NewLine);
                return;
            }
            byte[] ciphersBytes = StrToByteArray(cipher);
            Array.Reverse(ciphersBytes);

            if (txtProtocol.Text == "SSLv30")
            {
                tlsconnect(server, port, ProtocolVersion.SSLv30, ciphersBytes);
                return;
            }

            if (txtProtocol.Text == "TLSv10")
            {
                tlsconnect(server, port, ProtocolVersion.TLSv10, ciphersBytes);
                return;
            }

            if (txtProtocol.Text == "TLSv11")
            {
                tlsconnect(server, port, ProtocolVersion.TLSv11, ciphersBytes);
                return;
            }

            if (txtProtocol.Text == "TLSv12")
            {
                tlsconnect(server, port, ProtocolVersion.TLSv12, ciphersBytes);
                return;
            }
        }

        //btnScan_Click() is used for scan button
        private void btnScan_Click(object sender, EventArgs e)
        {
            UInt16 port;
            if (!UInt16.TryParse(txtServerPort.Text, out port))
            {
                txtOutPut.AppendText("The port number is invalid. Please check." + Environment.NewLine);
                return;
            }

            string server = txtServerUrl.Text;
            var regexServer = @"^(([a-z_A-Z0-9]|[a-z_A-Z0-9][a-z_A-Z0-9\-]*[a-z_A-Z0-9])\.)*([A-Z_a-z0-9]|[A-Z_a-z0-9][A-Z_a-z0-9\-]*[A-Z_a-z0-9])$";
            var matchServer = Regex.Match(server, regexServer);
            if (!matchServer.Success)
            {
                txtOutPut.AppendText("The server url is invalid." + Environment.NewLine);
                return;
            }

            try
            {
                TcpClient tcpClient = new TcpClient(server, port);
                tcpClient.Close();
            }
            catch (Exception econnectionException)
            {
                txtOutPut.AppendText("Failed to connect to server: " + server + ":" + port + Environment.NewLine);
                txtOutPut.AppendText(econnectionException.Message + Environment.NewLine);
                return;
            }

            txtOutPut.AppendText("Start scan for sslv2... " + Environment.NewLine);
            sslv2connect(server, port);
            txtOutPut.AppendText("Scan for sslv2 finished." + Environment.NewLine + Environment.NewLine);
            txtOutPut.Refresh();

            foreach (ProtocolVersion protocolVersion in (ProtocolVersion[])Enum.GetValues(typeof(ProtocolVersion)))
            {
                txtOutPut.AppendText("Start scan for " + protocolVersion + Environment.NewLine);
                txtOutPut.Refresh();
                List<byte> cipherSuitesBytes = new List<byte>();
                byte[] cipherSuitesTemp = new byte[2];
                byte[] ciphers = new byte[2];
                foreach (TLSCipherSuite cipherSuites in (TLSCipherSuite[])Enum.GetValues(typeof(TLSCipherSuite)))
                {
                    cipherSuitesTemp = (byte[])BitConverter.GetBytes((ushort)cipherSuites);
                    Array.Reverse(cipherSuitesTemp);
                    cipherSuitesBytes.AddRange(cipherSuitesTemp);
                }

                //if (debug == 3)
                //{
                //    foreach (byte b in cipherSuitesBytes)
                //        txtOutPut.AppendText(b.ToString("X2") + " ");
                //}

                do
                {
                    ciphers = TlsScan(server, port, protocolVersion, cipherSuitesBytes);
                    for (int i = 0; i < (cipherSuitesBytes.Count - 1); i += 2)
                    {
                        if (cipherSuitesBytes[i] == ciphers[0] && cipherSuitesBytes[i + 1] == ciphers[1])
                        {
                            cipherSuitesBytes.RemoveRange(i, 2);
                            break;
                        }
                    }

                } while (ciphers != unknowCipherSuite);

                txtOutPut.AppendText("Scan for " + protocolVersion  + " is finished."+ Environment.NewLine + Environment.NewLine);
                txtOutPut.Refresh();
            }
            txtOutPut.AppendText("Task completed." + Environment.NewLine);


        }

        //checkBoxQuickTest_CheckedChanged() is used to switch off ciphers and protocols when we select scan option
        private void checkBoxQuickTest_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBoxQuickTest.Checked == true)
            {
                txtProtocol.Enabled = true;
                txtCipher.Enabled = true;
                btnScan.Enabled = false;
                btnConnect.Enabled = true;
            }
            if (checkBoxQuickTest.Checked == false)
            {
                txtProtocol.Enabled = false;
                txtCipher.Enabled = false;
                btnScan.Enabled = true;
                btnConnect.Enabled = false;
            }
        }

        //sslv2connect() is used to send sslv2 ClientHello message
        private void sslv2connect(string server, Int32 port)
        {
            List<string> sslv20CipherSuitesSupported = new List<string>();
            using (TcpClient tcpClient = new TcpClient(server, port))
            {
                using (NetworkStream netWorkStream = tcpClient.GetStream())
                {
                    tcpClient.ReceiveTimeout = 3000;
                    tcpClient.SendTimeout = 3000;
                    netWorkStream.ReadTimeout = 3000;
                    netWorkStream.WriteTimeout = 3000;

                    // Define List<byte> used to store client and server stream
                    List<byte> sslv2ClientHello = new List<byte>();
                    List<byte> sslv2ServerHello = new List<byte>();

                    // Define bytes buffer to read server response
                    byte[] readBuffer = new byte[1];

                    // Generate sslv2ClientHello message
                    byte[] challenge = new byte[16];
                    Random random = new Random();
                    random.NextBytes(challenge);

                    sslv2ClientHello.AddRange(new byte[] { 0x80, 0x00 });                   // Length 
                    sslv2ClientHello.Add(0x01);                                             // Client Hello
                    sslv2ClientHello.AddRange(new byte[] { 0x00, 0x02 });                   // SSL Version (0x0002)
                    sslv2ClientHello.AddRange(new byte[] { 0x00, 0x18 });                   // Cipher Spec Length
                    sslv2ClientHello.AddRange(new byte[] { 0x00, 0x00 });                   // Session ID Length
                    sslv2ClientHello.AddRange(new byte[] { 0x00, 0x10 });                   // Challenge Length
                    sslv2ClientHello.AddRange(new byte[] { 0x00, 0x00, 0x00 });             // NULL_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x01, 0x00, 0x80 });             // RC4_128_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x02, 0x00, 0x80 });             // RC4_128_EXPORT40_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x03, 0x00, 0x80 });             // RC2_128_CBC_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x04, 0x00, 0x80 });             // RC2_128_CBC_EXPORT40_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x05, 0x00, 0x80 });             // IDEA_128_CBC_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x06, 0x00, 0x40 });             // DES_64_CBC_WITH_MD5
                    sslv2ClientHello.AddRange(new byte[] { 0x07, 0x00, 0xC0 });             // DES_192_EDE3_CBC_WITH_MD5                   
                    sslv2ClientHello.AddRange(challenge);                                   // Challenge

                    // Calculate the real length of the payload and replace
                    int temp = sslv2ClientHello.ToArray().Length - 2;
                    byte sslv2ClientHelloLength = Convert.ToByte((ushort)temp);
                    sslv2ClientHello.RemoveRange(1, 1);
                    sslv2ClientHello.Insert(1, sslv2ClientHelloLength);

                    // Debug sslv2ClientHello
                    if (debug == 1)
                    {
                        txtOutPut.AppendText(Environment.NewLine + "----------------------Print sslv2ClientHello Trace------------------------" + Environment.NewLine);
                        foreach (byte i in sslv2ClientHello)
                        {
                            txtOutPut.AppendText(i.ToString("X2") + " ");
                        }
                    }

                    // sslv2ClientHello response
                    netWorkStream.Write(sslv2ClientHello.ToArray(), 0, sslv2ClientHello.ToArray().Length);
                    do
                    {
                        netWorkStream.Read(readBuffer, 0, readBuffer.Length);
                        foreach (byte b in readBuffer)
                            sslv2ServerHello.Add(b);
                    } while (netWorkStream.DataAvailable);

                    if (debug == 1)
                    {
                        txtOutPut.AppendText(Environment.NewLine + "----------------------Print sslv2ServerHello Trace------------------------" + Environment.NewLine);
                        foreach (byte c in sslv2ServerHello)
                        {
                            txtOutPut.AppendText(c.ToString("X2") + " ");
                        }
                    }

                    // Check sslv2ClientHello length
                    if (sslv2ServerHello.Count < 64)
                    {
                        if (debug == 2)
                        {
                            txtOutPut.AppendText(Environment.NewLine + "SSLv20 ServerHello Length is less than 64, invalid." + Environment.NewLine);
                        }
                        return;
                    }
                    else if (sslv2ServerHello[2] != 4)
                    {
                        if (debug == 2)
                        {
                            txtOutPut.AppendText(Environment.NewLine + "SSLv20 Server did not send a ServerHello message." + Environment.NewLine);
                        }
                        return;
                    }
                    else if (sslv2ServerHello[6] != 2)
                    {
                        if (debug == 2)
                        {
                            txtOutPut.AppendText(Environment.NewLine + "SSLv20 SeverHello did not indicate SSLv2." + Environment.NewLine);
                        }
                        return;
                    }
                    else
                    {
                        // Get certificate length
                        byte[] certLenBytes = sslv2ServerHello.Skip(7).Take(2).ToArray();
                        Array.Reverse(certLenBytes);
                        int certificateLength = BitConverter.ToUInt16(certLenBytes, 0);

                        // Get cipher specs length
                        byte[] cipherSpecLenBytes = sslv2ServerHello.Skip(9).Take(2).ToArray();
                        Array.Reverse(cipherSpecLenBytes);
                        int cipherSpecLen = BitConverter.ToUInt16(cipherSpecLenBytes, 0);

                        // test if the cipher specs are valid
                        byte[] cipherSpecs = sslv2ServerHello.Skip(13 + certificateLength).Take(cipherSpecLen).ToArray();
                        if (cipherSpecs.Length % 3 != 0)
                        {
                            txtOutPut.AppendText(Environment.NewLine + "Invalid list of ciphers." + Environment.NewLine);
                        }
                        else
                        {
                            // Add sslv20CipherSuitesSupported into list
                            for (int x = 0; x < cipherSpecs.Length; x += 3)
                            {
                                byte[] cSpec = new byte[4];
                                cSpec[0] = 0x00;
                                Array.Copy(cipherSpecs.Skip(x).Take(3).ToArray(), 0, cSpec, 1, 3);
                                string cSpecValue = "0x" + BitConverter.ToString(cSpec, 1).Replace("-", "");
                                Array.Reverse(cSpec);

                                string csName = Enum.GetName(typeof(SSLv2CipherSuite), BitConverter.ToInt32(cSpec, 0));
                                if (csName.Length > 0)
                                    sslv20CipherSuitesSupported.Add("SSLv20 Cipher: " + csName + "    " + cSpecValue + "    insecure");
                                else
                                    sslv20CipherSuitesSupported.Add("SSLv20 Cipher: UNKNOWN");
                            }
                            //Display sslv20CipherSuitesSupported with Red color
                            //txtOutPut.AppendText("Supported SSL V2 Ciphers: " + Environment.NewLine);
                            foreach (string line in sslv20CipherSuitesSupported)
                            {
                                txtOutPut.SelectionColor = Color.Red;
                                txtOutPut.AppendText(line + Environment.NewLine);
                            }
                        }
                    }
                }
            }
            txtOutPut.AppendText(Environment.NewLine);
        }

        //tlsconnect() is used to send a single ciphersuite when we choose sslv3 and tls protocols
        private void tlsconnect(string server, Int32 port, ProtocolVersion protocolVersion, byte[] ciphersBytes )
        {
            using (TcpClient tcpClient = new TcpClient(server, port))
            {
                using (NetworkStream netWorkstream = tcpClient.GetStream())
                {
                    tcpClient.ReceiveTimeout = 3000;
                    tcpClient.SendTimeout = 3000;
                    netWorkstream.ReadTimeout = 3000;
                    netWorkstream.WriteTimeout = 3000;

                    List<byte> clientHello = new List<byte>();
                    List<byte> serverHello = new List<byte>();

                    UInt32 unixTimestamp = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                    byte[] unixTimestampBytes = (byte[])BitConverter.GetBytes(unixTimestamp);
                    Array.Reverse(unixTimestampBytes);
                    byte[] protocolVersionBytes = (byte[])BitConverter.GetBytes((ushort)protocolVersion);
                    Array.Reverse(protocolVersionBytes);

                    byte[] cipherSuitesBytes = ciphersBytes;
                    Array.Reverse(cipherSuitesBytes);

                    byte[] clientRandom = new byte[28];
                    Random random = new Random();
                    random.NextBytes(clientRandom);

                    clientHello.Add(0x16);                                      // CLient Hello Handshake [0]
                    clientHello.AddRange(protocolVersionBytes);                 // Version [1,2]
                    clientHello.AddRange(new byte[] { 0x00, 0x00 });            // SSL/TLS Payload length [3,4]
                    clientHello.Add(0x01);                                      // Client Hello [5]
                    clientHello.AddRange(new byte[] { 0x00, 0x00, 0x00 });      // SSL/TLS Client Hello Payload length [6-8]
                    clientHello.AddRange(protocolVersionBytes);                 // Version [9,10]
                    clientHello.AddRange(unixTimestampBytes);                   // GMT Unix Time [11-14]
                    clientHello.AddRange(clientRandom);                         // Random Bytes [15-42]
                    clientHello.Add(0x00);                                      // Session ID length [43]
                    clientHello.AddRange(new byte[] { 0x00, 0x02 });            // Cipher Suite Length (2 bytes) [44,45]
                    clientHello.AddRange(cipherSuitesBytes);                    // Ciphersuites [46,47]
                    clientHello.Add(0x01);                                      // Compression Methods [48]
                    clientHello.Add(0x00);                                      // null [49]

                    int clientHelloLength = clientHello.ToArray().Length;
                    clientHello.RemoveRange(3, 2);
                    clientHello.InsertRange(3, (BitConverter.GetBytes((ushort)(clientHelloLength - 5))).Reverse());
                    clientHello.RemoveRange(7, 2);
                    clientHello.InsertRange(7, (BitConverter.GetBytes((ushort)(clientHelloLength - 9))).Reverse());

                    byte[] cSpec = new byte[4];
                    cSpec[0] = 0x00;
                    cSpec[1] = 0x00;
                    cSpec[2] = ciphersBytes[0];
                    cSpec[3] = ciphersBytes[1];
                    string cSpecValue = "0x" + BitConverter.ToString(cSpec, 2).Replace("-", "");
                    Array.Reverse(cSpec);

                    try
                    {
                        string ciphersiutesName = Enum.GetName(typeof(TLSCipherSuite), BitConverter.ToInt32(cSpec, 0));
                        if (debug == 3)
                        {
                            txtOutPut.AppendText("----------------------sslv3 and Tls ClientHello Trace Start------------------------" + Environment.NewLine);
                            foreach (byte c in clientHello)
                            {
                                txtOutPut.AppendText(c.ToString("X2") + " ");
                            }
                            txtOutPut.AppendText(Environment.NewLine + "----------------------sslv3 and Tls ClientHello Trace Stop------------------------" + Environment.NewLine);
                        }

                        netWorkstream.Write(clientHello.ToArray(), 0, clientHello.ToArray().Length);

                        byte[] readBuffer = new byte[1];

                        do
                        {
                            netWorkstream.Read(readBuffer, 0, readBuffer.Length);
                            foreach (byte b in readBuffer)
                                serverHello.Add(b);
                        }
                        while (netWorkstream.DataAvailable);

                        if (debug == 3)
                        {
                            txtOutPut.AppendText("----------------------sslv3 and Tls ServerHello Trace Start------------------------" + Environment.NewLine);
                            foreach (byte b in serverHello)
                            {
                                txtOutPut.AppendText(b.ToString("X2") + " ");
                            }
                            txtOutPut.AppendText(Environment.NewLine + "----------------------sslv3 and Tls ServerHello Trace Stop------------------------" + Environment.NewLine);
                        }

                        if (serverHello.Count < 64)
                        {
                            txtOutPut.AppendText(protocolVersion + " Cipher: " + ciphersiutesName + " " + cSpecValue + " is disabled." + Environment.NewLine);
                            return;
                        }

                        if (serverHello[0] != 0x16)
                        {
                            txtOutPut.AppendText(protocolVersion + " Server did not send a Handshake message." + Environment.NewLine);
                            txtOutPut.AppendText(protocolVersion + " Cipher: " + ciphersiutesName + " " + cSpecValue + " is disabled." + Environment.NewLine);
                            return;
                        }

                        if (serverHello[1] != protocolVersionBytes[0] || serverHello[2] != protocolVersionBytes[1])
                        {
                            txtOutPut.AppendText(protocolVersion + " ServerHello was a different version." + Environment.NewLine);
                            txtOutPut.AppendText(protocolVersion + " Cipher: " + ciphersiutesName + " " + cSpecValue + " is disabled." + Environment.NewLine);
                            return;
                        }

                        if (serverHello[5] != 0x02)
                        {
                            txtOutPut.AppendText(protocolVersion + " Server did not send a ServerHello message." + Environment.NewLine);
                            txtOutPut.AppendText(protocolVersion + " Cipher: " + ciphersiutesName + " " + cSpecValue + " is disabled." + Environment.NewLine);
                            return;
                        }

                        txtOutPut.AppendText(protocolVersion + " Cipher: " + ciphersiutesName + " " + cSpecValue + " is enabled." + Environment.NewLine);
                    }
                    catch (System.NullReferenceException)
                    {
                        txtOutPut.AppendText("Ciphersuite is UNKNOWN, please input correct Ciphersuite" + Environment.NewLine);
                    } 
                }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
            }
        }

        //TlsCipherName() is used to return related Ciphersuite name
        public string TlsCipherName(byte[] cSpec)
        {
            byte[] cSpecTemp = new byte[4];
            cSpecTemp[0] = 0x00;
            cSpecTemp[1] = 0x00;
            Array.Copy(cSpec, 0, cSpecTemp, 2, 2);
            Array.Reverse(cSpecTemp);
            string csName = Enum.GetName(typeof(TLSCipherSuite), BitConverter.ToInt32(cSpecTemp, 0));
            return csName;
        }

        //txtProtocol_TextUpdate() is used to switch off ciphers when we select sslv2
        private void txtProtocol_TextUpdate(object sender, EventArgs e)
        {
            if (txtProtocol.Text == "SSLv20")
                txtCipher.Enabled = false;
            else
                txtCipher.Enabled = true;
        }
        
        //StrToByteArray() is used to convert string like "C008" to array {0xC0,0x08} and return the ciphersuite array
        public static byte[] StrToByteArray(string str)
        {
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            for (int i = 0; i < str.Length; i += 2)
                hexres.Add(hexindex[str.Substring(i, 2)]);

            return hexres.ToArray();
        }

        //ClientHello() is used to generate ClientHello stream used in sslv3 and above protocol and return ClientHello array
        public static List<byte> ClientHello(byte[] protocolVersionBytes, byte[] unixTimestampBytes, byte[] clientRandom, byte[] cipherSuitesLengthBytes, List<byte> cipherSuitesBytes)
        {
            List<byte> clientHelloTemp = new List<byte>();
            clientHelloTemp.Add(0x16);                                      // CLient Hello Handshake [0]
            clientHelloTemp.AddRange(protocolVersionBytes);                 // Version [1,2]
            clientHelloTemp.AddRange(new byte[] { 0x00, 0x00 });            // SSL/TLS Payload length [3,4]
            clientHelloTemp.Add(0x01);                                      // Client Hello [5]
            clientHelloTemp.AddRange(new byte[] { 0x00, 0x00, 0x00 });      // SSL/TLS Client Hello Payload length [6-8]
            clientHelloTemp.AddRange(protocolVersionBytes);                 // Version [9,10]
            clientHelloTemp.AddRange(unixTimestampBytes);                   // GMT Unix Time [11-14]
            clientHelloTemp.AddRange(clientRandom);                         // Random Bytes [15-42]
            clientHelloTemp.Add(0x00);                                      // Session ID length [43]
            clientHelloTemp.AddRange(cipherSuitesLengthBytes);            // Cipher Suite Length (2 bytes) [44,45]
            clientHelloTemp.AddRange(cipherSuitesBytes);                    // Ciphersuites
            clientHelloTemp.Add(0x01);                                      // Compression Methods
            clientHelloTemp.Add(0x00);                                      // null

            int clientHelloLength = clientHelloTemp.ToArray().Length;
            clientHelloTemp.RemoveRange(3, 2);
            clientHelloTemp.InsertRange(3, (BitConverter.GetBytes((ushort)(clientHelloLength - 5))).Reverse());
            clientHelloTemp.RemoveRange(7, 2);
            clientHelloTemp.InsertRange(7, (BitConverter.GetBytes((ushort)(clientHelloLength - 9))).Reverse());
            return clientHelloTemp;
        }

        //TlsScan() is used to test ciphersuites and return support ciphersuite from ServerHello message
        public byte[] TlsScan(string server, int port, ProtocolVersion protocolVersion, List<byte> cipherSuitesBytes)
        {
            using (TcpClient tcpClient = new TcpClient(server, port))
            {
                using (NetworkStream netWorkstream = tcpClient.GetStream())
                {
                    tcpClient.ReceiveTimeout = 3000;
                    tcpClient.SendTimeout = 3000;
                    netWorkstream.ReadTimeout = 3000;
                    netWorkstream.WriteTimeout = 3000;

                    List<byte> clientHello = new List<byte>();
                    List<byte> serverHello = new List<byte>();

                    UInt32 unixTimestamp = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                    byte[] unixTimestampBytes = (byte[])BitConverter.GetBytes(unixTimestamp);
                    Array.Reverse(unixTimestampBytes);
                    byte[] protocolVersionBytes = (byte[])BitConverter.GetBytes((ushort)protocolVersion);
                    Array.Reverse(protocolVersionBytes);

                    byte[] clientRandom = new byte[28];
                    Random random = new Random();
                    random.NextBytes(clientRandom);
                    byte[] cipherSuitesLengthBytes = (byte[])BitConverter.GetBytes((ushort)cipherSuitesBytes.Count);
                    Array.Reverse(cipherSuitesLengthBytes);

                    clientHello = ClientHello(protocolVersionBytes, unixTimestampBytes, clientRandom, cipherSuitesLengthBytes, cipherSuitesBytes);
                    int clientHelloLength = clientHello.ToArray().Length;
                    clientHello.RemoveRange(3, 2);
                    clientHello.InsertRange(3, (BitConverter.GetBytes((ushort)(clientHelloLength - 5))).Reverse());
                    clientHello.RemoveRange(7, 2);
                    clientHello.InsertRange(7, (BitConverter.GetBytes((ushort)(clientHelloLength - 9))).Reverse());

                    if (debug == 3)
                    {
                        txtOutPut.AppendText("----------------------sslv3 and Tls ClientHello Trace Start------------------------" + Environment.NewLine);
                        foreach (byte b in clientHello)
                            txtOutPut.AppendText(b.ToString("X2") + " ");
                        txtOutPut.AppendText(Environment.NewLine + "----------------------sslv3 and Tls ClientHello Trace Stop------------------------" + Environment.NewLine);
                        txtOutPut.Refresh();
                    }
                    

                    netWorkstream.Write(clientHello.ToArray(), 0, clientHello.ToArray().Length);

                    byte[] readBuffer = new byte[1];

                    do
                    {
                        netWorkstream.Read(readBuffer, 0, readBuffer.Length);
                        foreach (byte b in readBuffer)
                            serverHello.Add(b);
                    }
                    while (netWorkstream.DataAvailable);

                    if (debug == 3)
                    {
                        txtOutPut.AppendText("----------------------sslv3 and Tls ServerHello Trace Start------------------------" + Environment.NewLine);
                        foreach (byte b in serverHello)
                           txtOutPut.AppendText(b.ToString("X2") + " ");
                        txtOutPut.AppendText(Environment.NewLine + "----------------------sslv3 and Tls ClientHello Trace Stop------------------------" + Environment.NewLine);
                        txtOutPut.Refresh();
                    }

                    if (serverHello.Count < 64)
                    {
                        return unknowCipherSuite;
                    }

                    if (serverHello[0] != 0x16)
                    {
                        return unknowCipherSuite;
                    }

                    if (serverHello[1] != protocolVersionBytes[0] || serverHello[2] != protocolVersionBytes[1])
                    {
                        return unknowCipherSuite;
                    }

                    if (serverHello[5] != 0x02)
                    {
                        return unknowCipherSuite;
                    }

                    byte sessionIdLength = serverHello.Skip(43).Take(1).ToArray()[0];
                    byte[] cipherSuite = serverHello.Skip(44 + (int)sessionIdLength).Take(2).ToArray();
                    string cipherSuites = TlsCipherName(cipherSuite);
                    string cipherSuitesHex = "0x" + BitConverter.ToString(cipherSuite).Replace("-", "");


                    if (Regex.Match(cipherSuites, @"(RC4)+|(EXPORT)+|(ADH)+|(NULL)+").Success)
                    {
                        txtOutPut.SelectionColor = Color.Brown;
                        txtOutPut.AppendText(protocolVersion + " Cipher: " + cipherSuites + "    " + cipherSuitesHex + "    insecure" +  Environment.NewLine);
                        txtOutPut.Refresh();
                    }
                    else
                    {
                        txtOutPut.SelectionColor = Color.Green;
                        txtOutPut.AppendText(protocolVersion + " Cipher: " + cipherSuites + "    " + cipherSuitesHex + Environment.NewLine);
                        txtOutPut.Refresh();
                    }

                    return cipherSuite;
                }
            }
        }
        
        public enum ProtocolVersion
        {
            SSLv30 = 0x0300,
            TLSv10 = 0x0301,
            TLSv11 = 0x0302,
            TLSv12 = 0x0303
        }

        enum SSLv2CipherSuite
        {
            NULL_MD5 = 0x000000,
            RC4_128_WITH_MD5 = 0x010080,
            RC4_128_EXPORT40_WITH_MD5 = 0x020080,
            RC2_128_CBC_WITH_MD5 = 0x030080,
            RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080,
            IDEA_128_CBC_WITH_MD5 = 0x050080,
            DES_64_CBC_WITH_MD5 = 0x060040,
            DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0,
            RC4_64_WITH_MD5 = 0x080080
        }

        enum SSLv3CipherSuite
        {
            RSA_WITH_NULL_MD5 = 0x0001,
            RSA_WITH_NULL_SHA = 0x0002,
            RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003,
            RSA_WITH_RC4_128_MD5 = 0x0004,
            RSA_WITH_RC4_128_SHA = 0x0005,
            RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006,
            RSA_WITH_IDEA_CBC_SHA = 0x0007,
            RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008,
            RSA_WITH_DES_CBC_SHA = 0x0009,
            RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
            DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B,
            DH_DSS_WITH_DES_CBC_SHA = 0x000C,
            DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
            DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E,
            DH_RSA_WITH_DES_CBC_SHA = 0x000F,
            DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
            DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
            DHE_DSS_WITH_DES_CBC_SHA = 0x0012,
            DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
            DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
            DHE_RSA_WITH_DES_CBC_SHA = 0x0015,
            DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
            DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017,
            DH_anon_WITH_RC4_128_MD5 = 0x0018,
            DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
            DH_anon_WITH_DES_CBC_SHA = 0x001A,
            DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,
            FORTEZZA_KEA_WITH_NULL_SHA = 0X001C,
            FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 0x001D,
            FORTEZZA_KEA_WITH_RC4_128_SHA = 0x001E
        }

        enum TLSCipherSuite
        {
            RSA_WITH_NULL_MD5 = 0x0001,
            RSA_WITH_NULL_SHA = 0x0002,
            RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003,
            RSA_WITH_RC4_128_MD5 = 0x0004,
            RSA_WITH_RC4_128_SHA = 0x0005,
            RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006,
            RSA_WITH_IDEA_CBC_SHA = 0x0007,
            RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008,
            RSA_WITH_DES_CBC_SHA = 0x0009,
            RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
            DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B,
            DH_DSS_WITH_DES_CBC_SHA = 0x000C,
            DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
            DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E,
            DH_RSA_WITH_DES_CBC_SHA = 0x000F,
            DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
            DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
            DHE_DSS_WITH_DES_CBC_SHA = 0x0012,
            DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
            DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
            DHE_RSA_WITH_DES_CBC_SHA = 0x0015,
            DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
            DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017,
            DH_anon_WITH_RC4_128_MD5 = 0x0018,
            DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
            DH_anon_WITH_DES_CBC_SHA = 0x001A,
            DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,
            FORTEZZA_KEA_WITH_NULL_SHA = 0X001C,
            FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 0x001D,
            FORTEZZA_KEA_WITH_RC4_128_SHA = 0x001E,
            TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
            TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
            TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
            TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034,
            TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
            TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
            TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
            TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
            TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A,
            TLS_RSA_WITH_NULL_SHA256 = 0x003B,
            TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
            TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
            TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E,
            TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F,
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040,
            TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041,
            TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042,
            TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043,
            TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044,
            TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045,
            TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
            TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068,
            TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069,
            TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,
            TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C,
            TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D,
            TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084,
            TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085,
            TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086,
            TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087,
            TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088,
            TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089,
            TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B,
            TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C,
            TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D,
            TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F,
            TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090,
            TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091,
            TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093,
            TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094,
            TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095,
            TLS_RSA_WITH_SEED_CBC_SHA = 0x0096,
            TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097,
            TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098,
            TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099,
            TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A,
            TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B,
            TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
            TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,
            TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,
            TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0,
            TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1,
            TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2,
            TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3,
            TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4,
            TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5,
            TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6,
            TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7,
            TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8,
            TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9,
            TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA,
            TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB,
            TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC,
            TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD,
            TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE,
            TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF,
            TLS_PSK_WITH_NULL_SHA256 = 0x00B0,
            TLS_PSK_WITH_NULL_SHA384 = 0x00B1,
            TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2,
            TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3,
            TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4,
            TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5,
            TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6,
            TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7,
            TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8,
            TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9,
            TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA,
            TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB,
            TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC,
            TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD,
            TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE,
            TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF,
            TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0,
            TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1,
            TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2,
            TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3,
            TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4,
            TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5,
            TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001,
            TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003,
            TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004,
            TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005,
            TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006,
            TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,
            TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B,
            TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D,
            TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E,
            TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F,
            TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
            TLS_ECDH_anon_WITH_NULL_SHA = 0xC015,
            TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017,
            TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018,
            TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019,
            TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A,
            TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B,
            TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C,
            TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D,
            TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E,
            TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F,
            TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020,
            TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021,
            TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,
            TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025,
            TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,
            TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029,
            TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
            TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D,
            TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
            TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031,
            TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032,
            TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034,
            TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035,
            TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036,
            TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037,
            TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038,
            TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039,
            TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A,
            TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B,
            TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C,
            TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D,
            TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E,
            TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F,
            TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040,
            TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041,
            TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042,
            TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043,
            TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044,
            TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045,
            TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046,
            TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047,
            TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048,
            TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049,
            TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A,
            TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B,
            TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C,
            TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D,
            TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E,
            TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F,
            TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050,
            TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051,
            TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052,
            TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053,
            TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054,
            TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055,
            TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056,
            TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057,
            TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058,
            TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059,
            TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A,
            TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B,
            TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C,
            TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D,
            TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E,
            TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F,
            TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060,
            TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061,
            TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062,
            TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063,
            TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064,
            TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065,
            TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066,
            TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067,
            TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068,
            TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069,
            TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A,
            TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B,
            TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C,
            TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D,
            TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E,
            TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F,
            TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070,
            TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071,
            TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072,
            TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073,
            TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074,
            TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075,
            TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076,
            TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077,
            TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078,
            TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079,
            TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A,
            TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B,
            TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C,
            TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D,
            TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E,
            TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F,
            TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080,
            TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081,
            TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082,
            TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083,
            TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084,
            TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085,
            TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086,
            TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087,
            TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088,
            TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089,
            TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A,
            TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B,
            TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C,
            TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D,
            TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E,
            TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F,
            TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090,
            TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091,
            TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092,
            TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093,
            TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094,
            TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095,
            TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096,
            TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097,
            TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098,
            TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099,
            TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A,
            TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B,
            TLS_RSA_WITH_AES_128_CCM = 0xC09C,
            TLS_RSA_WITH_AES_256_CCM = 0xC09D,
            TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E,
            TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F,
            TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0,
            TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1,
            TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2,
            TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3,
            TLS_PSK_WITH_AES_128_CCM = 0xC0A4,
            TLS_PSK_WITH_AES_256_CCM = 0xC0A5,
            TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6,
            TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7,
            TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8,
            TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9,
            TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA,
            TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB,
            TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC,
            TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD,
            TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE,
            TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF,
            //TLS_ECCPWD_WITH_AES_128_GCM_SHA256 = 0xC0B0,
            //TLS_ECCPWD_WITH_AES_256_GCM_SHA384 = 0xC0B1,
            //TLS_ECCPWD_WITH_AES_128_CCM_SHA256 = 0xC0B2,
            //TLS_ECCPWD_WITH_AES_256_CCM_SHA384 = 0xC0B3,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,
            TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,
            TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,
            TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD,
            TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
            //TLS_FALLBACK_SCSV = 0x5600
            //TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xD001,
            //TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xD002,
            //TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = 0xD003,
            //TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 0xD005
        }
     }
}
