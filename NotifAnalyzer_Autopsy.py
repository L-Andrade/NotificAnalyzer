import jarray
import json
import inspect
import subprocess
import os
from java.io import File
from java.lang import System
from java.util.logging import Level
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JComponent
from javax.swing import JTextField
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils

class NotificationAnalyzerDataSourceIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Windows Notifications Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses and analyzes information regarding Windows 10's Notifications"

    def getModuleVersionNumber(self):
        return "0.1"

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            settings = GenericIngestModuleJobSettings()
        self.settings = settings
        return NotificationAnalyzerWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return NotificationAnalyzerDataSourceIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class NotificationAnalyzerDataSourceIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(NotificationAnalyzerDataSourceIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        self.temp_dir = Case.getCurrentCase().getTempDirectory()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        
        self.use_undark = self.local_settings.getSetting("undark") == "true"
        self.use_mdg = self.local_settings.getSetting("mdg") == "true"
        self.use_crawler = self.local_settings.getSetting("crawler") == "true"
        self.use_b2l = self.local_settings.getSetting("b2l") == "true"
        self.python_path = self.local_settings.getSetting("python_path")
        self.log(Level.INFO, "Python path: " + str(self.python_path))
        
        # Generic attributes
        self.att_id = self.create_attribute_type('NA_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ID", blackboard)
        self.att_type = self.create_attribute_type('NA_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type", blackboard)
        self.att_created_time = self.create_attribute_type('NA_CREATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Created time", blackboard)
        self.att_modified_time = self.create_attribute_type('NA_UPDATED_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Updated time", blackboard)
        self.att_expiry_time = self.create_attribute_type('NA_EXPIRY_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Expiry time", blackboard)
        self.att_arrival_time = self.create_attribute_type('NA_ARRIVAL_TIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Arrival time", blackboard)

        # Notification handler attributes
        self.att_handler_primary_id = self.create_attribute_type('NA_HANDLER_PRIMARY_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Primary ID", blackboard)
        self.att_parent_id = self.create_attribute_type('NA_PARENT_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent ID", blackboard)
        self.att_wns_id = self.create_attribute_type('NA_WNS_ID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "WNS ID", blackboard)
        self.att_wnf_event_name = self.create_attribute_type('NA_WNF_EVENT_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "WNF Event Name", blackboard)
        self.att_system_data_property_set = self.create_attribute_type('NA_SYSTEM_DATA_PROPERTY_SET', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "System data property set", blackboard)
        self.att_app_name = self.create_attribute_type('NA_APP_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "App name (Your Phone)", blackboard)

        # Notification attributes
        self.att_payload = self.create_attribute_type('NA_PAYLOAD', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Payload", blackboard)
        self.att_payload_type = self.create_attribute_type('NA_PAYLOAD_TYPE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Content format", blackboard)
        
        # DB User Version
        self.att_db_uv = self.create_attribute_type('NA_DB_UV', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SQLite User Version", blackboard)

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        moduleName = NotificationAnalyzerDataSourceIngestModuleFactory.moduleName

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "wpndatabase.db") 

        num_files = len(files)
        self.log(Level.INFO, "Found " + str(num_files) + " Notification databases")
        progressBar.switchToDeterminate(num_files)
        for file in files:
            full_path = (file.getParentPath() + file.getName())
            split = full_path.split('/')
            try:
                username = split[-11]
                guid = split[-4]
            except IndexError:
                username = "UNKNOWN"
                guid = "UNKNOWN"
            self.art_notification = self.create_artifact_type("NA_NOTIFICATION_" + guid + "_" + username,"User " + username + " - Notifications", blackboard)
            self.art_notification_handler = self.create_artifact_type("NA_NOTIFICATION_HANDLER_" + guid + "_" + username,"User " + username + " - Notification handler", blackboard)
            self.art_settings = self.create_artifact_type("NA_SETTINGS_" + guid + "_" + username,"User " + username + " - Database settings", blackboard)

            temp_file = os.path.join(self.temp_dir, file.getName())
            ContentUtils.writeToFile(file, File(temp_file))

            path_to_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NotifAnalyzer.py")
            result_file = os.path.join(self.temp_dir, "result.json")
            self.log(Level.INFO, "Saving notification output to " + str(result_file))
            with open(os.path.join(self.temp_dir, 'na-debug.log'), 'w') as f:
                subprocess.Popen([self.python_path, path_to_script, '-p', temp_file, '-j', result_file],stdout=f).communicate()
            with open(result_file) as json_file:
                data = json.load(json_file)
                
                art = file.newArtifact(self.art_settings.getTypeID())
                user_version = data["user_version"]
                art.addAttribute(BlackboardAttribute(self.att_db_uv, moduleName, str(user_version)))
                self.index_artifact(blackboard, art, self.art_settings)
                
                for key, handler in data["assets"].iteritems():
                    for child_key, value in handler.iteritems():
                        if not value and child_key <> "Notifications":
                            handler[child_key] = "N/A"
                    if "AppName" in handler:
                        app_name = handler["AppName"]
                    else:
                        app_name = "N/A"
                    art = file.newArtifact(self.art_notification_handler.getTypeID())
                    art.addAttribute(BlackboardAttribute(self.att_id, moduleName, str(handler["HandlerId"])))
                    art.addAttribute(BlackboardAttribute(self.att_handler_primary_id, moduleName, str(handler["HandlerPrimaryId"])))
                    art.addAttribute(BlackboardAttribute(self.att_parent_id, moduleName, str(handler["ParentId"])))
                    art.addAttribute(BlackboardAttribute(self.att_app_name, moduleName, app_name))
                    art.addAttribute(BlackboardAttribute(self.att_created_time, moduleName, str(handler["CreatedTime"])))
                    art.addAttribute(BlackboardAttribute(self.att_modified_time, moduleName, str(handler["ModifiedTime"])))
                    art.addAttribute(BlackboardAttribute(self.att_wnf_event_name, moduleName, str(handler["WNFEventName"])))
                    art.addAttribute(BlackboardAttribute(self.att_type, moduleName, str(handler["HandlerType"])))
                    art.addAttribute(BlackboardAttribute(self.att_wns_id, moduleName, str(handler["WNSId"])))
                    art.addAttribute(BlackboardAttribute(self.att_system_data_property_set, moduleName, str(handler["SystemDataPropertySet"])))
                    self.index_artifact(blackboard, art, self.art_notification_handler)

                    for notification in handler["Notifications"]:
                        art = file.newArtifact(self.art_notification.getTypeID())
                        art.addAttribute(BlackboardAttribute(self.att_type, moduleName, str(notification["Type"])))
                        art.addAttribute(BlackboardAttribute(self.att_payload_type, moduleName, str(notification["PayloadType"])))
                        art.addAttribute(BlackboardAttribute(self.att_payload, moduleName, str(notification["Payload"])))
                        expiry_time = self.windows_filetime_to_epoch(notification["ExpiryTime"])
                        art.addAttribute(BlackboardAttribute(self.att_expiry_time, moduleName, expiry_time))
                        arrival_time = self.windows_filetime_to_epoch(notification["ArrivalTime"])
                        art.addAttribute(BlackboardAttribute(self.att_arrival_time, moduleName, arrival_time))

                        self.index_artifact(blackboard, art, self.art_notification)
            self.log(Level.INFO, "Processed successfully...")

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Notifications Analyzer Data Source Ingest Module", "[NA] Finished processing %d Notification databases" % num_files)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def windows_filetime_to_epoch(self, windows_filetime):
        return windows_filetime / 10000000 - 11644473600

    def index_artifact(self, blackboard, artifact, artifact_type):
        try:
            # Index the artifact for keyword search
            blackboard.indexArtifact(artifact)
        except Blackboard.BlackboardException as e:
            self.log(Level.INFO, "Error indexing artifact " + artifact.getDisplayName() + " " +str(e))
        # Fire an event to notify the UI and others that there is a new log artifact
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(NotificationAnalyzerDataSourceIngestModuleFactory.moduleName,
                            artifact_type, None))

    def create_artifact_type(self, art_name, art_desc, blackboard):
        try:
            art = blackboard.getOrAddArtifactType(art_name, "NA: " + art_desc)
            # self.art_list.append(art)
        except Exception as e :
            self.log(Level.INFO, "Error getting or adding artifact type: " + art_desc + " " + str(e))
        return art

    def create_attribute_type(self, att_name, type_name, att_desc, blackboard):
        try:
            att_type = blackboard.getOrAddAttributeType(att_name, type_name, att_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding attribute type: " + att_desc + " " + str(e))
        return att_type

# UI that is shown to user for each ingest job so they can configure the job.
class NotificationAnalyzerWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def checkBoxEventUndark(self, event):
        if self.checkboxUndark.isSelected():
            self.local_settings.setSetting("undark", "true")
        else:
            self.local_settings.setSetting("undark", "false")

    def checkBoxEventMdg(self, event):
        if self.checkboxMdg.isSelected():
            self.local_settings.setSetting("mdg", "true")
        else:
            self.local_settings.setSetting("mdg", "false")

    def checkBoxEventCrawler(self, event):
        if self.checkboxCrawler.isSelected():
            self.local_settings.setSetting("crawler", "true")
        else:
            self.local_settings.setSetting("crawler", "false")

    def checkBoxEventB2l(self, event):
        if self.checkboxB2l.isSelected():
            self.local_settings.setSetting("b2l", "true")
        else:
            self.local_settings.setSetting("b2l", "false")
    
    def textFieldEventPythonPath(self, event):
        self.local_settings.setSetting("python_path", self.textFieldPythonPath.getText())

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        # self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        panel1 = JPanel()
        panel1.setLayout(BoxLayout(panel1, BoxLayout.Y_AXIS))
        panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.labelPythonPathText = JLabel("Python path: ")
        self.textFieldPythonPath = JTextField(1)
        self.buttonSavePythonPath = JButton("Save", actionPerformed=self.textFieldEventPythonPath)

        self.labelCheckText = JLabel("Run recoveries: ")

        self.checkboxUndark = JCheckBox("Undark", actionPerformed=self.checkBoxEventUndark)
        self.checkboxMdg = JCheckBox("MGD Delete Parser", actionPerformed=self.checkBoxEventMdg)
        self.checkboxCrawler = JCheckBox("WAL Crawler", actionPerformed=self.checkBoxEventCrawler)
        self.checkboxB2l = JCheckBox("bring2lite", actionPerformed=self.checkBoxEventB2l)
        
        self.checkboxUndark.setSelected(True)
        self.checkboxMdg.setSelected(True)
        
        self.add(self.labelPythonPathText)
        panel1.add(self.textFieldPythonPath)
        panel1.add(self.buttonSavePythonPath)

        panel1.add(self.labelCheckText)
        panel1.add(self.checkboxUndark)
        panel1.add(self.checkboxMdg)
        panel1.add(self.checkboxCrawler)
        panel1.add(self.checkboxB2l)
        self.add(panel1)

    def customizeComponents(self):
        # Set defaults if not set
        if not self.local_settings.getSetting("undark"):
            self.local_settings.setSetting("undark", "true")
        if not self.local_settings.getSetting("mdg"):
            self.local_settings.setSetting("mdg", "true")
        if not self.local_settings.getSetting("python_path"):
            self.local_settings.setSetting("python_path", "python")

        # Update checkboxes with stored settings
        self.checkboxUndark.setSelected(self.local_settings.getSetting("undark") == "true")
        self.checkboxMdg.setSelected(self.local_settings.getSetting("mdg") == "true")
        self.checkboxCrawler.setSelected(self.local_settings.getSetting("crawler") == "true")
        self.checkboxB2l.setSelected(self.local_settings.getSetting("b2l") == "true")
        self.textFieldPythonPath.setText(self.local_settings.getSetting("python_path"))

    # Return the settings used
    def getSettings(self):
        return self.local_settings