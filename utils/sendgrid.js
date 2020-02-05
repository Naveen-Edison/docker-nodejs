const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.sendgrid_api_key);

let sendMail = async function(email_array, template_id, replacements) {
  try {

    const msg = {
      to: email_array,
      from: process.env.from_email,
      templateId: template_id,
      dynamic_template_data: replacements,
    };

    let response = await sgMail.send(msg);
    if (response) {
      return true;
    } else {
      return false;
    }
  } catch (err) {
    return false;
  }
};

module.exports = {
  sendMail,
};
