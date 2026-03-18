const fs = require('fs');
const path = require('path');


let templateData = fs.readFileSync(
    path.join(__dirname, "..", "src", "template.html"), { encoding: 'utf8' }
);

let jsData = fs.readFileSync(
    path.join(__dirname, "..", "src", "IVernarus1.js"), { encoding: 'utf8' }
);

jsData = jsData.substring( jsData.indexOf("class ") );


templateData = templateData.replace("###INCLUDE_IVERNARUS###", jsData);

fs.writeFileSync(
    path.join(__dirname, "..", "dist", "ivernarus1.html"),
    templateData,
    { encoding: 'utf8' }
);
