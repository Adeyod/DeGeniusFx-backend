import nodemailer from 'nodemailer';

// export default async (email, text, subject) => {
//   try {
//     const transporter = nodemailer.createTransport({
//       host: process.env.HOST,
//       port: Number(process.env.EMAIL_PORT),
//       service: process.env.SERVICE,
//       secure: Boolean(process.env.SECURE),
//       auth: {
//         // TODO: replace `user` and `pass` values from <https://forwardemail.net>
//         user: process.env.USER,
//         pass: process.env.PASS,
//       },
//       // host: "smtp.forwardemail.net",
//       // port: 465,
//       // secure: true,
//       // auth: {
//       //   // TODO: replace `user` and `pass` values from <https://forwardemail.net>
//       //   user: "REPLACE-WITH-YOUR-ALIAS@YOURDOMAIN.COM",
//       //   pass: "REPLACE-WITH-YOUR-GENERATED-PASSWORD",
//       // },
//     });

//     const mailOptions = {
//       from: process.env.USER,
//       to: email,
//       subject: subject,
//       text: text,
//     };

//     await transporter.sendMail(mailOptions, (err, response) => {
//       if (err) {
//         console.log(err);
//         // res.json({
//         //   message: 'Error sending email',
//         // });
//         response('Error sending email');
//       } else {
//         response('Verification email sent to your email address');
//         // res.json({
//         //   message: 'Verification email sent to your email address',
//         // });
//         console.log('Email sent successfully');
//       }
//     });
//   } catch (error) {
//     console.log('Email not sent');
//     console.log(error);
//   }
// };

// export default sendEmail;

const verifyMail = async (email, link) => {
  try {
    let transporter = nodemailer.createTransport({
      host: process.env.HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.SECURE,
      service: process.env.SERVICE,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    // send email
    let info = await transporter.sendMail({
      from: process.env.USER, // email address of the website owner
      to: email, //clients email from the database
      subject: 'Account Verification',
      text: 'Welcome',

      // body of the mail
      html: `
      <div>
      <p>Thank you for registering. Please verify your account as this link expires in 30 mins</p>
      <a href=${link}>Click here to verify your account...</a>
      </div>
      `,
    });
    console.log('Email send successfully');
  } catch (error) {
    console.log(error, 'Error sending email');
    return;
  }
};

const passwordReset = async (email, link) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.SECURE,
      service: process.env.SERVICE,
      auth: {
        // TODO: replace `user` and `pass` values from <https://forwardemail.net>
        user: process.env.USER,
        pass: process.env.PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    // send mail with defined transport object
    const info = await transporter.sendMail({
      from: process.env.USER, // sender address
      to: email, // list of receivers

      subject: 'Reset password', // Subject line
      text: 'Welcome', // plain text body
      html: `
      <div>
      <p>This message was sent for you to reset your password. It expires in 10mins.</p>
      <a href=${link}>Click Here to reset your password</a>
      </div>
      `, // html body
    });

    console.log('Message sent: %s', info.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>

    //
    // NOTE: You can go to https://forwardemail.net/my-account/emails to see your email delivery status and preview
    //       Or you can use the "preview-email" npm package to preview emails locally in browsers and iOS Simulator
    //       <https://github.com/forwardemail/preview-email>
    //
  } catch (error) {
    console.log(error);
    return;
  }
};

export { verifyMail, passwordReset };
