import jwt from "jsonwebtoken";

const userAuth = (req, res, next) => {
  const { token } = req.cookies;
  if (!token) {
    return res.json({ success: false, message: "Unauthorized, Login Again" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.id) {
      req.user = { id: decoded.id };
    } else {
      return res.json({ success: false, message: "Not authorized, Login Again" });
    }

    next();
  } catch (error) {
     res.json({ success: false, message: error.message });
  }
};

export default userAuth;

