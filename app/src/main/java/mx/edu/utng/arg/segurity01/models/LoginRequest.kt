package mx.edu.utng.database.arg.segurity01.models

/**
 * Datos necesarios para hacer login
 * Esta información se enviará al servidor
 */
data class LoginRequest(
    val email: String,
    val password: String
)