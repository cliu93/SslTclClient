namespace SslTcpClient
{
    partial class SslTcpClient
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SslTcpClient));
            this.lblServerUrl = new System.Windows.Forms.Label();
            this.txtServerUrl = new System.Windows.Forms.TextBox();
            this.lblServerPort = new System.Windows.Forms.Label();
            this.txtServerPort = new System.Windows.Forms.TextBox();
            this.lblProtocol = new System.Windows.Forms.Label();
            this.txtOutPut = new System.Windows.Forms.RichTextBox();
            this.btnConnect = new System.Windows.Forms.Button();
            this.btnReset = new System.Windows.Forms.Button();
            this.txtProtocol = new System.Windows.Forms.ComboBox();
            this.lblQuickTest = new System.Windows.Forms.Label();
            this.checkBoxQuickTest = new System.Windows.Forms.CheckBox();
            this.btnScan = new System.Windows.Forms.Button();
            this.lblCipher = new System.Windows.Forms.Label();
            this.txtCipher = new System.Windows.Forms.TextBox();
            this.btnListCipher = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // lblServerUrl
            // 
            this.lblServerUrl.AutoSize = true;
            this.lblServerUrl.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblServerUrl.Location = new System.Drawing.Point(13, 23);
            this.lblServerUrl.Name = "lblServerUrl";
            this.lblServerUrl.Size = new System.Drawing.Size(86, 16);
            this.lblServerUrl.TabIndex = 0;
            this.lblServerUrl.Text = "Server Url: ";
            // 
            // txtServerUrl
            // 
            this.txtServerUrl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtServerUrl.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtServerUrl.Location = new System.Drawing.Point(107, 20);
            this.txtServerUrl.Name = "txtServerUrl";
            this.txtServerUrl.Size = new System.Drawing.Size(350, 22);
            this.txtServerUrl.TabIndex = 1;
            // 
            // lblServerPort
            // 
            this.lblServerPort.AutoSize = true;
            this.lblServerPort.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblServerPort.Location = new System.Drawing.Point(13, 55);
            this.lblServerPort.Name = "lblServerPort";
            this.lblServerPort.Size = new System.Drawing.Size(94, 16);
            this.lblServerPort.TabIndex = 0;
            this.lblServerPort.Text = "Server Port: ";
            // 
            // txtServerPort
            // 
            this.txtServerPort.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtServerPort.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtServerPort.Location = new System.Drawing.Point(107, 51);
            this.txtServerPort.Name = "txtServerPort";
            this.txtServerPort.Size = new System.Drawing.Size(351, 22);
            this.txtServerPort.TabIndex = 1;
            this.txtServerPort.Text = "443";
            // 
            // lblProtocol
            // 
            this.lblProtocol.AutoSize = true;
            this.lblProtocol.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblProtocol.Location = new System.Drawing.Point(13, 87);
            this.lblProtocol.Name = "lblProtocol";
            this.lblProtocol.Size = new System.Drawing.Size(70, 16);
            this.lblProtocol.TabIndex = 0;
            this.lblProtocol.Text = "Protocol:";
            // 
            // txtOutPut
            // 
            this.txtOutPut.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtOutPut.Location = new System.Drawing.Point(9, 210);
            this.txtOutPut.Name = "txtOutPut";
            this.txtOutPut.Size = new System.Drawing.Size(452, 555);
            this.txtOutPut.TabIndex = 2;
            this.txtOutPut.Text = "";
            // 
            // btnConnect
            // 
            this.btnConnect.Location = new System.Drawing.Point(241, 181);
            this.btnConnect.Name = "btnConnect";
            this.btnConnect.Size = new System.Drawing.Size(114, 23);
            this.btnConnect.TabIndex = 3;
            this.btnConnect.Text = "Connect";
            this.btnConnect.UseVisualStyleBackColor = true;
            this.btnConnect.Click += new System.EventHandler(this.btnConnect_Click);
            // 
            // btnReset
            // 
            this.btnReset.Location = new System.Drawing.Point(13, 181);
            this.btnReset.Name = "btnReset";
            this.btnReset.Size = new System.Drawing.Size(96, 23);
            this.btnReset.TabIndex = 3;
            this.btnReset.Text = "Reset";
            this.btnReset.UseVisualStyleBackColor = true;
            this.btnReset.Click += new System.EventHandler(this.btnReset_Click);
            // 
            // txtProtocol
            // 
            this.txtProtocol.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtProtocol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.txtProtocol.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtProtocol.FormattingEnabled = true;
            this.txtProtocol.Items.AddRange(new object[] {
            "SSLv20",
            "SSLv30",
            "TLSv10",
            "TLSv11",
            "TLSv12"});
            this.txtProtocol.Location = new System.Drawing.Point(107, 84);
            this.txtProtocol.Name = "txtProtocol";
            this.txtProtocol.Size = new System.Drawing.Size(350, 24);
            this.txtProtocol.TabIndex = 4;
            this.txtProtocol.TextChanged += new System.EventHandler(this.txtProtocol_TextUpdate);
            // 
            // lblQuickTest
            // 
            this.lblQuickTest.AutoSize = true;
            this.lblQuickTest.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblQuickTest.Location = new System.Drawing.Point(13, 154);
            this.lblQuickTest.Name = "lblQuickTest";
            this.lblQuickTest.Size = new System.Drawing.Size(90, 16);
            this.lblQuickTest.TabIndex = 0;
            this.lblQuickTest.Text = "Quick Test: ";
            // 
            // checkBoxQuickTest
            // 
            this.checkBoxQuickTest.AutoSize = true;
            this.checkBoxQuickTest.Location = new System.Drawing.Point(104, 156);
            this.checkBoxQuickTest.Name = "checkBoxQuickTest";
            this.checkBoxQuickTest.Size = new System.Drawing.Size(15, 14);
            this.checkBoxQuickTest.TabIndex = 5;
            this.checkBoxQuickTest.UseVisualStyleBackColor = true;
            this.checkBoxQuickTest.CheckedChanged += new System.EventHandler(this.checkBoxQuickTest_CheckedChanged);
            // 
            // btnScan
            // 
            this.btnScan.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnScan.Location = new System.Drawing.Point(361, 181);
            this.btnScan.Name = "btnScan";
            this.btnScan.Size = new System.Drawing.Size(98, 23);
            this.btnScan.TabIndex = 3;
            this.btnScan.Text = "Scan";
            this.btnScan.UseVisualStyleBackColor = true;
            this.btnScan.Click += new System.EventHandler(this.btnScan_Click);
            // 
            // lblCipher
            // 
            this.lblCipher.AutoSize = true;
            this.lblCipher.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblCipher.Location = new System.Drawing.Point(13, 121);
            this.lblCipher.Name = "lblCipher";
            this.lblCipher.Size = new System.Drawing.Size(96, 16);
            this.lblCipher.TabIndex = 0;
            this.lblCipher.Text = "CipherSuite: ";
            // 
            // txtCipher
            // 
            this.txtCipher.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtCipher.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtCipher.Location = new System.Drawing.Point(104, 118);
            this.txtCipher.Name = "txtCipher";
            this.txtCipher.Size = new System.Drawing.Size(351, 22);
            this.txtCipher.TabIndex = 1;
            // 
            // btnListCipher
            // 
            this.btnListCipher.Location = new System.Drawing.Point(115, 181);
            this.btnListCipher.Name = "btnListCipher";
            this.btnListCipher.Size = new System.Drawing.Size(120, 23);
            this.btnListCipher.TabIndex = 3;
            this.btnListCipher.Text = "List Ciphers codes";
            this.btnListCipher.UseVisualStyleBackColor = true;
            this.btnListCipher.Click += new System.EventHandler(this.ListAllCiphers);
            // 
            // SslTcpClient
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(470, 771);
            this.Controls.Add(this.checkBoxQuickTest);
            this.Controls.Add(this.txtProtocol);
            this.Controls.Add(this.btnReset);
            this.Controls.Add(this.btnScan);
            this.Controls.Add(this.btnListCipher);
            this.Controls.Add(this.btnConnect);
            this.Controls.Add(this.txtOutPut);
            this.Controls.Add(this.txtCipher);
            this.Controls.Add(this.txtServerPort);
            this.Controls.Add(this.txtServerUrl);
            this.Controls.Add(this.lblQuickTest);
            this.Controls.Add(this.lblCipher);
            this.Controls.Add(this.lblProtocol);
            this.Controls.Add(this.lblServerPort);
            this.Controls.Add(this.lblServerUrl);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "SslTcpClient";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "SslTcpClient";
            this.Load += new System.EventHandler(this.SslTcpClient_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblServerUrl;
        private System.Windows.Forms.TextBox txtServerUrl;
        private System.Windows.Forms.Label lblServerPort;
        private System.Windows.Forms.TextBox txtServerPort;
        private System.Windows.Forms.Label lblProtocol;
        private System.Windows.Forms.RichTextBox txtOutPut;
        private System.Windows.Forms.Button btnConnect;
        private System.Windows.Forms.Button btnReset;
        private System.Windows.Forms.ComboBox txtProtocol;
        private System.Windows.Forms.Label lblQuickTest;
        private System.Windows.Forms.CheckBox checkBoxQuickTest;
        private System.Windows.Forms.Button btnScan;
        private System.Windows.Forms.Label lblCipher;
        private System.Windows.Forms.TextBox txtCipher;
        private System.Windows.Forms.Button btnListCipher;
    }
}

