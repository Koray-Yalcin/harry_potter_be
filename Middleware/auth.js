import jwt from 'jsonwebtoken';

const auth = async (req, res, next) => {
  try {
    const accessToken = req.headers.authorization.split(' ')[1]

    let decodedToken;

    if (accessToken) {
      decodedToken = jwt.verify(accessToken, 'ACCESS_TOKEN_SECRET')
      req.creatorId = decodedToken?.id
    } else {
      decodedToken = jwt.decode(accessToken)

      req.creatorId = decodedToken?.sub
    }

    next()
  } catch (error) {
    console.log(error)
  }
}

export default auth