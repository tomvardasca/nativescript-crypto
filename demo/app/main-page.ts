import * as observable from "tns-core-modules/data/observable";
import * as pages from "tns-core-modules/ui/page";

import { HelloWorldModel } from "./main-view-model";
import { NSCrypto } from "nativescript-crypto";

let helloWorldModel: HelloWorldModel;
// Event handler for Page 'loaded' event attached in main-page.xml
export function pageLoaded(args: observable.EventData) {
  // Get the event sender
  let page = <pages.Page>args.object;
  helloWorldModel = new HelloWorldModel();
  page.bindingContext = helloWorldModel;
}

const crypto = new NSCrypto();

export function sha256() {
  let start = new Date().getTime();
  console.log(
    "crypto.hash 256: ",
    crypto.hash("abc", "sha256"),
    " elapsed ",
    new Date().getTime() - start + "ms"
  );
}

export function random() {
  let start = new Date().getTime();
  console.log(
    "crypto.random: ",
    crypto.secureRandomBytes(32),
    " elapsed ",
    new Date().getTime() - start + "ms"
  );
}

export function deriveSecureKey() {
  let start = new Date().getTime();
  console.log(
    "crypto.deriveSecureKey: ",
    JSON.stringify(
      crypto.deriveSecureKey(
        "123456",
        32,
        null,
        null,
        null // ,
        // "scryptsalsa208sha256"
      )
    ),
    " elapsed ",
    new Date().getTime() - start + "ms"
  );
}
