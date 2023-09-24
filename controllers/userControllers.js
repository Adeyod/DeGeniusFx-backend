import User from '../models/userModels.js';

const updateUser = async (req, res, next) => {
  const user = await User.findOne({ email });
};
const getUserProfile = async (req, res, next) => {
  const user = {
    _id: req.user._id,
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    email: req.user.email,
    tel: req.user.firstName,
    address: req.user.tel,
    image: req.user.image,
  };
  res.json({
    status: 200,
    user,
  });
};

const getUser = async (req, res, next) => {};
export { updateUser, getUserProfile };
