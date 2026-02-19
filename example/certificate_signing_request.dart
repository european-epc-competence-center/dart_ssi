import 'dart:io';

import 'package:dart_ssi/util.dart';
import 'package:dart_ssi/wallet.dart';

void main() async {
  var wallet = WalletStore('testCsr');
  await wallet.openBoxes(password: 'pwd');
  await wallet.initializeIssuer(keyType: KeyType.ed25519);

  //generate Did
  var did = wallet.getStandardIssuerDid(KeyType.ed25519);

  //generate Certificate Signing Request (CSR)
  var csr = await buildCsrForDid(wallet, did!,
      organization: 'Hochschule Mittweida',
      organizationalUnit: 'Fakultät CB',
      emailAddress: 'someAdmin@hs-mittweida.de',
      city: 'Mittweida',
      countryCode: 'DE',
      state: 'Sachsen');

  //write CSR to file
  var file = File('exampleData/flutterCSR.pem');
  file.openWrite();
  file.writeAsStringSync(csr);
}
