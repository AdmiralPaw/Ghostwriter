import lxml.etree as etree

# Child Elements
from ghostwriter.reporting.parsers.parser_template import Parser

NESSUS_FIELDS = ['risk_factor', 'vuln_publication_date', 'description',
                 'plugin_output', 'solution', 'synopsis',
                 'exploit_available', 'exploitability_ease', 'exploited_by_malware',
                 'plugin_publication_date', 'plugin_modification_date']
# Attribute Fields
ATTRIB_FIELDS = ['severity', 'pluginFamily', 'pluginID', 'pluginName']

SEVERITIES = {0: "Informational",
              1: "Low",
              2: "Medium",
              3: "High",
              4: "Critical"}

UNIQUE_IP_LIST = list()


class NessusParser(Parser):
    def parse_file(self, file):
        """
            Paring the nessus file and generating information
        """
        context = etree.iterparse(file, events=('start', 'end',))
        context = iter(context)
        event, root = next(context)
        if not root.tag in ["NessusClientData_v2"]:
            return None
        vuln_data = list()
        host_data = list()
        device_data = list()
        # cpe_data = []
        host_cvss = dict()
        cvss_scores = dict()
        ms_process_info = list()
        count_ip_seen = 0
        start_tag = None
        for event, elem in context:
            host_properties = {}
            if event == 'start' and elem.tag == 'ReportHost' and start_tag is None:
                start_tag = elem.tag
                continue
            if event == 'end' and elem.tag == start_tag:
                host_properties['name'] = self.get_attrib_value(elem, 'name')
                host_properties['host-ip'] = ''
                host_properties['host-fqdn'] = ''
                host_properties['netbios-name'] = ''

                # CVSS Map Generation
                for i in range(0, 5):
                    cvss_scores[i] = {
                        'cvss_temporal_score': 0, 'cvss_base_score': 0}

                # Building Host Data
                if elem.find('HostProperties') is not None:
                    for child in elem.find('HostProperties'):
                        if child.get('name') in ['host-ip'] and child.text is not None:
                            host_properties['host-ip'] = child.text
                        if child.get('name') in ['host-fqdn'] and child.text is not None:
                            host_properties['host-fqdn'] = child.text
                        if child.get('name') in ['netbios-name'] and child.text is not None:
                            host_properties['netbios-name'] = child.text
                    host_data.append(host_properties.copy())

                # Counting Total IP's seen
                count_ip_seen += 1
                # Counting Unique IP's seen
                if host_properties['host-ip'] not in UNIQUE_IP_LIST:
                    UNIQUE_IP_LIST.append(host_properties['host-ip'])

                # Iter over each item
                for child in elem.iter('ReportItem'):
                    cve_item_list = list()
                    if child.find("cve") is not None:
                        for cve in child.iter("cve"):
                            cve_item_list.append(cve.text)

                    # Bugtraq ID Per Item
                    bid_item_list = list()
                    if child.find("bid") is not None:
                        for bid in child.iter("bid"):
                            bid_item_list.append(bid.text)

                    vuln_properties = host_properties

                    for field in NESSUS_FIELDS:
                        if field == 'solution':
                            vuln_properties['mitigation'] = self.get_child_value(child, field)
                        elif field == 'synopsis':
                            vuln_properties['replication_steps'] = self.get_child_value(child, field)
                        elif field == 'plugin_output':
                            vuln_properties['references'] = self.get_child_value(child, field)
                        else:
                            vuln_properties[field] = self.get_child_value(
                                child, field)

                    for field in ATTRIB_FIELDS:
                        if field == 'pluginID':
                            vuln_properties['parserID'] = self.get_attrib_value(child, field)
                        elif field == 'pluginName':
                            vuln_properties['title'] = self.get_attrib_value(child, field)
                        elif field == 'pluginFamily':
                            vuln_properties['finding_type'] = self.get_attrib_value(child, field)
                        elif field == 'severity':
                            temp = self.get_attrib_value(child, field)
                            if int(temp) in SEVERITIES:
                                vuln_properties['severity'] = SEVERITIES[int(temp)]
                                vuln_properties['severity_weight'] = int(temp)
                        else:
                            vuln_properties[field] = self.get_attrib_value(
                                child, field)
                    vuln_properties['impact'] = ''
                    vuln_properties['affected_entities'] = ''
                    vuln_properties['host_detection_techniques'] = ''
                    vuln_properties['network_detection_techniques'] = ''
                    vuln_properties['finding_guidance'] = ''
                    vuln_properties['port'] = self.get_attrib_value(child, "port")
                    vuln_properties['bid'] = ";\n".join(bid_item_list)
                    vuln_properties['cve'] = ";\n".join(cve_item_list)

                    vuln_data.append(vuln_properties.copy())
                host_data.append(host_properties.copy())
                host_cvss[host_properties['host-ip']] = cvss_scores
                elem.clear()
                for ancestor in elem.xpath('ancestor-or-self::*'):
                    while ancestor.getprevious() is not None:
                        del ancestor.getparent()[0]
        del context
        return vuln_data
        # , device_data, ms_process_info, count_ip_seen, host_cvss

    @staticmethod
    def get_attrib_value(currelem, attrib):
        """
            Get element attribute or return emtpy
        """
        if currelem.get(attrib) is not None:
            return currelem.get(attrib)
        return ''

    @staticmethod
    def get_child_value(currelem, getchild):
        """
            Return child element value
        """
        if currelem.find(getchild) is not None:
            return currelem.find(getchild).text
        return ''

