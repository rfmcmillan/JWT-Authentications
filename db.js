const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Sequelize = require('sequelize');
const { STRING } = Sequelize.DataTypes;
//this prevents logging of the Sequelize commands
const config = {
  logging: false,
};
//this allows you to enter 'LOGGING=true npm run test:dev' to delete the above
//config and log the different commands
if (process.env.LOGGING) {
  delete config.logging;
}
const db = new Sequelize(
  process.env.DATABASE_URL || 'postgres://localhost/acme_db'
);

const User = db.define('user', {
  username: STRING,
  password: STRING,
});

User.addHook('beforeSave', async function (user) {
  if (user._changed.has('password')) {
    user.password = await bcrypt.hash(user.password, 10);
  }
});

const syncAndSeed = async () => {
  await db.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw' },
    { username: 'larry', password: 'larry_pw' },
    { username: 'moe', password: 'moe_pw' },
  ];
  const [lucy, larry, moe] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      larry,
      moe,
    },
  };
};

User.authenticate = async function ({ username, password }) {
  const user = await User.findOne({
    where: { username },
  });
  if (user && (await bcrypt.compare(password, user.password))) {
    return jwt.sign({ id: user.id }, process.env.JWT);
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

User.byToken = async function (token) {
  try {
    const { id } = await jwt.verify(token, process.env.JWT);
    const user = await User.findByPk(id);
    if (user) {
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  } catch (err) {
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
