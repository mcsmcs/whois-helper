var exec = require('child_process').exec;
var moment = require('moment');

var dateHelper = function(value){
    return moment(value.replace(/,/g,':')).format('dddd, MMMM Do YYYY') + ' (' + moment(value.replace(/,/g,':')).fromNow() + ')';
}

exports.index = function(req, res){

    var command = 'whois ' + req.params.domain;
    var child = exec(command, function(err, stdout, stderr){
        
        if (err){ console.log(err); }
        console.log(stderr);

        var whois = {};
        whois.registrar = {};
        whois.registrant = {};
        whois.dates = {};
        whois.status = [];
        whois.nameservers = [];

        var regexActions = {
            'Registrar': function(){ whois.registrar.name = value; },
            'Registrar WHOIS Server': function(){ whoisServer = value; },
            'Registrar URL': function(){ whois.registrar.url = value; },
            'Registrar IANA ID': function(){ whois.registrar.iana = value; },
            'Registrar Abuse Contact Email': function(){ whois.registrar.abuseEmail = value; },
            'Registrar Abuse Contact Phone': function(){ whois.registrar.abusePhone = value; },
            'Updated Date': function(){ whois.dates.updated = dateHelper(value); },
            'Creation Date': function(){ whois.dates.created = dateHelper(value); },
            'Registrar Registration Expiration Date': function(){ whois.dates.expiration = dateHelper(value); },
            'Expiration Date': function(){ whois.dates.expiration = dateHelper(value); },
            'Status': function(){ whois.status.push(value); },
            'Registrant Name': function(){ whois.registrant.name = value; },
            'Registrant Organization': function(){ whois.registrant.organization = value; },
            'Registrant Street': function(){ whois.registrant.street = value; },
            'Registrant City': function(){ whois.registrant.city = value; },
            'Registrant State/Province': function(){ whois.registrant.state = value; },
            'Registrant Postal Code': function(){ whois.registrant.zip = value; },
            'Registrant Country': function(){ whois.registrant.country = value; },
            'Registrant Phone': function(){ whois.registrant.phone = value; },
            'Registrant Phone Ext': function(){ whois.registrant.ext = value; },
            'Registrant Fax': function(){ whois.registrant.fax = value; },
            'Registrant Fax Ext': function(){ whois.registrant.faxext = value; },
            'Registrant Email': function(){ whois.registrant.email = value; },
            'Name Server': function(){ whois.nameservers.push(value); }
        }

        var lines = stdout.split('\n');
        for (index in lines){
 
                if (/:/.test(lines[index])){
                    var label = lines[index].split(':')[0].trim();
                    var value = lines[index].split(':').slice(1).join().trim();

                    if (regexActions[label]){ regexActions[label](value); }
                }
        }

        res.send(whois);
    });

};
