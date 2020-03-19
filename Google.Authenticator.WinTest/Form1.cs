using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace Google.Authenticator.WinTest
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            txtAccountTitle.Text = "QRTestAccount";
            txtSecretKey.Text = "f68f1fe894d548a1bbc66165c46e61eb"; //Guid.NewGuid().ToString().Replace("-", "");
        }

        private void btnSetup_Click(object sender, EventArgs e)
        {
            var tfA = new TwoFactorAuthenticator();
            var setupCode = tfA.GenerateSetupCode(txtAccountTitle.Text, txtAccountTitle.Text, txtSecretKey.Text, false, 3);

            //WebClient wc = new WebClient();
            using (var ms = new MemoryStream(Convert.FromBase64String(setupCode.QrCodeSetupImageUrl.Replace("data:image/png;base64,", ""))))
                pbQR.Image = Image.FromStream(ms);

            txtSetupCode.Text = "Account: " + setupCode.Account + Environment.NewLine +
                "Secret Key: " + txtSecretKey.Text + Environment.NewLine +
                "Encoded Key: " + setupCode.ManualEntryKey;
        }

        private void btnTest_Click(object sender, EventArgs e)
        {
            var tfA = new TwoFactorAuthenticator();
            var result = tfA.ValidateTwoFactorPin(txtSecretKey.Text, txtCode.Text);

            MessageBox.Show(result ? "Validated!" : "Incorrect", "Result");
        }

        private void btnGetCurrentCode_Click(object sender, EventArgs e)
        {
            txtCurrentCodes.Text = string.Join(Environment.NewLine, new TwoFactorAuthenticator().GetCurrentPins(txtSecretKey.Text));
        }

        private void btnDebugTest_Click(object sender, EventArgs e)
        {

        }
    }
}
