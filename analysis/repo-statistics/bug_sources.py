import xlsxwriter

from helpers.data_helper import load_evolution_projects_json
from helpers.mongo_helper import MongoProjectIterator


def main():
    projects = load_evolution_projects_json()
    security_bugs = ['HRS_REQUEST_PARAMETER_TO_COOKIE',
                     'HRS_REQUEST_PARAMETER_TO_HTTP_HEADER',
                     'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
                     'SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING',
                     'XSS_REQUEST_PARAMETER_TO_JSP_WRITER',
                     'XSS_REQUEST_PARAMETER_TO_SEND_ERROR',
                     'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER']

    sql_bugs = {'activemq-all', 'activemq', 'activeobjects', 'cas-workflow',
                'ebxmlms', 'efaps-kernel', 'fabric3-binding-ws',
                'geotk-metadata-sql',
                'jackrabbit-standalone', 'james', 'james-server-mailets',
                'jcaptcha-all',
                'jdatabaseimport', 'jetty-webapp', 'jonas-jms-manager',
                'joram', 'kernel',
                'makumba', 'MetaModel', 'nunaliit2-adhocQueries', 'openjms',
                'org.openl.rules.eclipse.ui.wizard', 'sandesha2-persistence',
                'servicemix-components', 'sesame', 'sonar-application',
                'sqltool',
                'sqltool-j5', 'squirrel-sql', 'torque', 'transactions-jta',
                'ujo-orm', 'xmlui'}

    xss_bugs = {'activemq-all', 'activemq-web', 'makumba', 'netcdf', 'opendap',
                'org.talend.esb.job.console', 'rdfbean-sparql', 'tika-app',
                'tuscany-domain-manager', 'tuscany-sca-all', 'webmin',
                'WebProxyPortlet',
                'whiteboard', 'activemq', 'apacheds', 'avro-tools',
                'css-validator',
                'dspace-jspui-api', 'dspace-lni-core', 'fabric3-binding-ws',
                'force-oauth',
                'groovysoap-all-jsr06', 'jackrabbit-standalone',
                'jetty-webapp', 'jftp',
                'makumba', 'MessAdmin-Core', 'myfaces', 'myfaces-all',
                'ocpsoft-pretty-faces',
                'org.apache.felix.webconsole', 'org.apache.sling.openidauth',
                'org.jbundle.util.webapp.redirect',
                'org.talend.esb.job.console',
                'pustefix-webservices-jaxws', 'sonar-application', 'vt-ldap'}

    input_bugs = set()
    input_bugs |= sql_bugs
    input_bugs |= xss_bugs

    total_projects = len(projects)
    count = 0

    workbook = xlsxwriter.Workbook('bug_sources.xlsx')
    worksheet = workbook.add_worksheet()
    row = 0

    print 'Found %d Projects' % (total_projects,)

    for p in projects:
        piter = MongoProjectIterator(p.group_id(), p.artifact_id(),
                                     fields=['JarMetadata.group_id',
                                             'JarMetadata.artifact_id',
                                             'JarMetadata.version',
                                             'JarMetadata.version_order',
                                             'BugCollection.BugInstance.category',
                                             'BugCollection.BugInstance.type',
                                             'BugCollection.BugInstance.SourceLine.classname',
                                             'BugCollection.BugInstance.SourceLine.start',
                                             'BugCollection.BugInstance.SourceLine.end'])
        doc_list = piter.documents_list()
        count += 1

        print '[%d:%d] %s||%s: %d versions' % (
            count, total_projects, p.group_id(), p.artifact_id(),
            len(doc_list))

        for d in doc_list:
            for bi in d.get('BugCollection', {}).get('BugInstance', []):
                if not isinstance(bi, dict):
                    # print 'Invalid BugInstance (%s)' % (bi,)
                    continue

                bug_c = bi.get('category', '')
                if bug_c == 'SECURITY':
                    bug_type = bi.get('type', None)

                    if bug_type is None:
                        print 'Invalid Type!'
                        continue

                    if bug_type in security_bugs:
                        if p.artifact_id() in input_bugs:
                            col = 0
                            source = bi.get('SourceLine', {})
                            worksheet.write(row, col, p.artifact_id())
                            if isinstance(source, list):
                                for i, j in enumerate(source):
                                    worksheet.write(row, col + 1 + i,
                                                    j.get('classname',
                                                          'NotSet'))
                                    worksheet.write(row, col + 2 + i,
                                                    j.get('start', 'NotSet'))
                                    worksheet.write(row, col + 3 + i,
                                                    j.get('end', 'NotSet'))
                            elif isinstance(source, dict):
                                worksheet.write(row, col + 1,
                                                source.get('classname',
                                                           'NotSet'))
                                worksheet.write(row, col + 2,
                                                source.get('start', 'NotSet'))
                                worksheet.write(row, col + 3,
                                                source.get('end', 'NotSet'))
                            row += 1

        print row


if __name__ == "__main__":
    main()
