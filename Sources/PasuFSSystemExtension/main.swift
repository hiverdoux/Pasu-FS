import Darwin
import EndpointSecurity
import Foundation

private enum EndpointClientFactory {
  nonisolated static func create(client: inout OpaquePointer?) -> es_new_client_result_t {
    es_new_client(&client) { _, _ in
      // The activation scaffold does not subscribe until policy lifecycle wiring is complete.
    }
  }
}

private func resultName(_ result: es_new_client_result_t) -> String {
  switch result {
  case ES_NEW_CLIENT_RESULT_SUCCESS: "SUCCESS"
  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: "ERR_INVALID_ARGUMENT"
  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: "ERR_INTERNAL"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: "ERR_NOT_ENTITLED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: "ERR_NOT_PERMITTED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: "ERR_NOT_PRIVILEGED"
  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: "ERR_TOO_MANY_CLIENTS"
  default: "UNKNOWN(\(result.rawValue))"
  }
}

var client: OpaquePointer?
let result = EndpointClientFactory.create(client: &client)
guard result == ES_NEW_CLIENT_RESULT_SUCCESS, client != nil else {
  fputs("Pasu FS system extension es_new_client: \(resultName(result))\n", stderr)
  exit(EXIT_FAILURE)
}

print("Pasu FS Endpoint Security system extension: ready")
dispatchMain()
