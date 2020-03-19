using System;

namespace Google.Authenticator.WebSample
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(Request.QueryString["key"]))
            {
                Response.Redirect("~/default.aspx?key=" + Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10));
            }

            lblSecretKey.Text = Request.QueryString["key"];

            var tfa = new TwoFactorAuthenticator();
            var setupInfo = tfa.GenerateSetupCode("Test Two Factor", "user@example.com", Request.QueryString["key"], false, 300);

            var qrCodeImageUrl = setupInfo.QrCodeSetupImageUrl;
            var manualEntrySetupCode = setupInfo.ManualEntryKey;

            imgQrCode.ImageUrl = "data:image/png;base64," + qrCodeImageUrl;
            lblManualSetupCode.Text = manualEntrySetupCode;
        }

        protected void btnValidate_Click(object sender, EventArgs e)
        {
            var tfa = new TwoFactorAuthenticator();
            var result = tfa.ValidateTwoFactorPin(Request.QueryString["key"], txtCode.Text);

            if (result)
            {
                lblValidationResult.Text = txtCode.Text + " is a valid PIN at UTC time " + DateTime.UtcNow.ToString();
                lblValidationResult.ForeColor = System.Drawing.Color.Green;
            }
            else
            {
                lblValidationResult.Text = txtCode.Text + " is not a valid PIN at UTC time " + DateTime.UtcNow.ToString();
                lblValidationResult.ForeColor = System.Drawing.Color.Red;
            }
        }
    }
}