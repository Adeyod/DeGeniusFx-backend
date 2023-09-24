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
      service: 'Gmail',
      port: 465,
      host: 'smtp.gmail.com',
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
      <a href=${link}>Click here to verify your account</a>
      </div>
      `,
    });
    console.log('Email send successfully');
  } catch (error) {
    console.log(error, 'Error sending email');
  }
};

export default verifyMail;
