import json

from helpers.data_helper import ArrayCount, save_to_file, load_evolution_projects_json
from helpers.mongo_helper import MongoProjectIterator


def main():
    projects = load_evolution_projects_json()
    results = {}
    security_bugs = ['HRS_REQUEST_PARAMETER_TO_COOKIE',
                     'HRS_REQUEST_PARAMETER_TO_HTTP_HEADER',
                     'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
                     'SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING',
                     'XSS_REQUEST_PARAMETER_TO_JSP_WRITER',
                     'XSS_REQUEST_PARAMETER_TO_SEND_ERROR',
                     'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER']

    sql_bugs = {'activemq-all', 'activemq', 'activeobjects', 'cas-workflow',
                'ebxmlms', 'efaps-kernel', 'fabric3-binding-ws', 'geotk-metadata-sql',
                'jackrabbit-standalone', 'james', 'james-server-mailets', 'jcaptcha-all',
                'jdatabaseimport', 'jetty-webapp', 'jonas-jms-manager', 'joram', 'kernel',
                'makumba', 'MetaModel', 'nunaliit2-adhocQueries', 'openjms',
                'org.openl.rules.eclipse.ui.wizard', 'sandesha2-persistence',
                'servicemix-components', 'sesame', 'sonar-application', 'sqltool',
                'sqltool-j5', 'squirrel-sql', 'torque', 'transactions-jta',
                'ujo-orm', 'xmlui'}

    xss_bugs = {'activemq-all', 'activemq-web', 'makumba', 'netcdf', 'opendap',
                'org.talend.esb.job.console', 'rdfbean-sparql', 'tika-app',
                'tuscany-domain-manager', 'tuscany-sca-all', 'webmin', 'WebProxyPortlet',
                'whiteboard', 'activemq', 'apacheds', 'avro-tools', 'css-validator',
                'dspace-jspui-api', 'dspace-lni-core', 'fabric3-binding-ws', 'force-oauth',
                'groovysoap-all-jsr06', 'jackrabbit-standalone', 'jetty-webapp', 'jftp',
                'makumba', 'MessAdmin-Core', 'myfaces', 'myfaces-all', 'ocpsoft-pretty-faces',
                'org.apache.felix.webconsole', 'org.apache.sling.openidauth',
                'org.jbundle.util.webapp.redirect', 'org.talend.esb.job.console',
                'pustefix-webservices-jaxws', 'sonar-application', 'vt-ldap'}

    input_bugs = set()
    input_bugs |= sql_bugs
    input_bugs |= xss_bugs

    total_projects = len(projects)
    count = 0

    print 'Found %d Projects' % (total_projects,)

    for p in projects:
        piter = MongoProjectIterator(p.group_id(), p.artifact_id(), fields=['JarMetadata.group_id', 'JarMetadata.artifact_id', 'JarMetadata.version', 'JarMetadata.version_order', 'BugCollection.BugInstance.category', 'BugCollection.BugInstance.type', 'BugCollection.BugInstance.Class.classname','BugCollection.BugInstance.Method.name', 'BugCollection.BugInstance.Field.name'])
        doc_list = piter.documents_list()
        proj_array_count = ArrayCount()
        bug_list = []
        count += 1

        print '[%d:%d] %s||%s: %d versions' % (count, total_projects, p.group_id(), p.artifact_id(), len(doc_list))

        for d in doc_list:
            for bi in d.get('BugCollection', {}).get('BugInstance', []):
                if not isinstance(bi, dict):
                    #print 'Invalid BugInstance (%s)' % (bi,)
                    continue

                bug_c = bi.get('category', '')
                if bug_c == 'SECURITY':
                    bug_type = bi.get('type', None)
                    
                    if bug_type is None:
                        print 'Invalid Type!'
                        continue

                    if bug_type in security_bugs:
                        if p.artifact_id() in input_bugs:
                            bug_category = 'INPUT_VALIDATION_BUGS'
                        else:
                            continue
                    else:
                        bug_category = 'SECURITY_REST'
                else:
                    bug_category = bug_c
                
                # create signature
                signatures_ids = []
                classnames = bi['Class']

                if isinstance(classnames, list):
                    for c in classnames:
                        signatures_ids.append(c.get('classname', 'NotSet'))
                elif isinstance(classnames, dict):
                    signatures_ids.append(classnames.get('classname', 'NotSet'))

                # methods
                methodnames = bi.get('Method', {})

                if isinstance(methodnames, list):
                    for m in methodnames:
                        signatures_ids.append(m.get('name', 'NotSet'))
                elif isinstance(methodnames, dict):
                    signatures_ids.append(methodnames.get('name', 'NotSet'))

                # fields
                fieldnames = bi.get('Field', {})
                if isinstance(fieldnames, list):
                    for f in fieldnames:
                        signatures_ids.append(f.get('name', 'NotSet'))
                elif isinstance(fieldnames, dict):
                    signatures_ids.append(fieldnames.get('name', 'NotSet'))

                type = bi['type']
                signature = '%s||%s||%s' % (bug_category, type, '||'.join(signatures_ids))

                # method
                if signature not in bug_list:
                    bug_list.append(signature)
                    proj_array_count.incr(bug_category)
                
                proj_array_count.incr('TOTAL_' + bug_category)

        print proj_array_count.get_series()
        results['%s||%s' % (p.group_id(), p.artifact_id())] = proj_array_count.get_series()

    save_to_file('data/bug_correlation_counters.json', json.dumps(results))


if __name__ == "__main__":
    main()
