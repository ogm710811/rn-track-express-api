const mongoose = require( 'mongoose' );
const bcrypt = require( 'bcrypt' );

const userSchema = new mongoose.Schema( {
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
} );

// implementing salting and hashing for each user password and saving to MongoDB
userSchema.pre( 'save', function ( next ) {
  const user = this;
  if ( !user.isModified( 'password' ) ) {
    return next();
  }

  bcrypt.genSalt( 10, ( err, salt ) => {
    if ( err ) {
      return next( err );
    }

    bcrypt.hash( user.password, salt, ( err, hash ) => {
      if ( err ) {
        return next( err );
      }
      user.password = hash;
      next();
    } )
  } )
} )

// comparing the password user entered when login with teh password saved in Mongo DB
userSchema.methods.comparePassword = function ( candidatePassword ) {
  const user = this;
  return new Promise( ( res, rej ) => {
    bcrypt.compare( candidatePassword, user.password, ( err, isMatch ) => {
      if ( err ) {
        return rej( err );
      }
      if ( !isMatch ) {
        return rej( false );
      }

      res(true);
    } )
  } )
}

mongoose.model( 'User', userSchema );
