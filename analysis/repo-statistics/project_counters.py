import json

from helpers.data_helper import load_vuln_projects_json, ArrayCount, save_to_file
from helpers.mongo_helper import MongoProjectIterator


def main():
    projects = load_vuln_projects_json()
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
        piter = MongoProjectIterator(p.group_id(), p.artifact_id(), fields=['JarMetadata.group_id', 'JarMetadata.artifact_id', 'JarMetadata.version', 'JarMetadata.jar_size', 'JarMetadata.version_order', 'JarMetadata.jar_last_modification_date', 'BugCollection.BugInstance.category', 'BugCollection.BugInstance.type', 'BugCollection.BugInstance.Class.classname','BugCollection.BugInstance.priority'])
        doc_list = piter.documents_list()
        documents = []
        count += 1

        print '[%d:%d] %s||%s: %d versions' % (count, total_projects, p.group_id(), p.artifact_id(), len(doc_list))

        for d in doc_list:
            doc_results = {'JarMetadata': d['JarMetadata']}
            doc_array_count = ArrayCount()
            sec_instances = []

            for bi in d.get('BugCollection', {}).get('BugInstance', []):
                if not isinstance(bi, dict):
                    print bi
                    continue

                bug_category = bi.get('category', '')

                # method
                if bug_category == 'SECURITY' or bug_category == 'MALICIOUS_CODE':
                    classnames = bi['Class']
                    classresults = []

                    if isinstance(classnames, list):
                        for c in classnames:
                            classresults.append(c.get('classname', 'NotSet'))
                    elif isinstance(classnames, dict):
                        classresults.append(classnames.get('classname', 'NotSet'))

                    sec_dict = {'Category' : bug_category,
                                'Type' : bi.get('type', 'NotSet'),
                                'Priority' : int(bi.get('priority', 0)),
                                'Class' : classresults}
                    sec_instances.append(sec_dict)

                # counters
                if bug_category == 'SECURITY':
                    bug_type = bi.get('type', None)
                    
                    if bug_type is None:
                        print 'Invalid Type!'
                        continue
                        
                    if bug_type in security_bugs:
                        if p.artifact_id() in input_bugs:
                            doc_array_count.incr('INPUT_VALIDATION_BUGS')
                        else:
                            continue
                    else:
                        doc_array_count.incr('SECURITY_REST')
                else:
                    doc_array_count.incr(bug_category)
                #doc_array_count.incr(bug_category)

            doc_results['Counters'] = doc_array_count.get_series()
            doc_results['SecurityBugs'] = sec_instances
            documents.append(doc_results)

        key = '%s||%s' % (p.group_id(), p.artifact_id())
        results[key] = {'group_id' : p.group_id(),
                        'artifact_id' : p.artifact_id(),
                        'version_count' : len(doc_list),
                        'versions' : documents}
        #print results

    save_to_file('data/project_counters.json', json.dumps(results))


if __name__ == "__main__":
    main()
