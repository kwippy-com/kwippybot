#include "purple.h"

#include <glib.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <syslog.h>
#include <mysql.h>
#include <string.h>
#include <unistd.h>
#include <gettext.h>
#include <stdio.h>
#include "defines.h"

#define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
	PurpleInputFunction function;
	guint result;
	gpointer data;
} PurpleGLibIOClosure;

struct gtuple {
	guint uid;
	guint aid;
	GTimeVal now;
	char hmd[1000];
};
char dbserver[80];
char dbuser[80];
char dbpassword[80];
char dbdatabase[80];
char pname[80];
char puser[80];
char ppass[80];
char ppid[80];
MYSQL *conn;
MYSQL_RES *res;
int pid;

void errreport(const char *str)
{
    syslog(LOG_LOCAL0, "%s (%m)", str);
}

MYSQL_ROW row;

static void purple_glib_io_destroy(gpointer data)
{
	g_free(data);
}

static gboolean purple_glib_io_invoke(GIOChannel *source, GIOCondition condition, gpointer data)
{
	PurpleGLibIOClosure *closure = data;
	PurpleInputCondition purple_cond = 0;

	if (condition & PURPLE_GLIB_READ_COND)
		purple_cond |= PURPLE_INPUT_READ;
	if (condition & PURPLE_GLIB_WRITE_COND)
		purple_cond |= PURPLE_INPUT_WRITE;

	closure->function(closure->data, g_io_channel_unix_get_fd(source),
			  purple_cond);

	return TRUE;
}

static guint glib_input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function,
							   gpointer data)
{
	PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
	GIOChannel *channel;
	GIOCondition cond = 0;

	closure->function = function;
	closure->data = data;

	if (condition & PURPLE_INPUT_READ)
		cond |= PURPLE_GLIB_READ_COND;
	if (condition & PURPLE_INPUT_WRITE)
		cond |= PURPLE_GLIB_WRITE_COND;

	channel = g_io_channel_unix_new(fd);
	closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
					      purple_glib_io_invoke, closure, purple_glib_io_destroy);

	g_io_channel_unref(channel);
	return closure->result;
}

static PurpleEventLoopUiOps glib_eventloops =
{
        g_timeout_add,
        g_source_remove,
        glib_input_add,
        g_source_remove,
        NULL,
#if GLIB_CHECK_VERSION(2,14,0)
        g_timeout_add_seconds,
#else
        NULL,
#endif

        /* padding */
        NULL,
        NULL,
        NULL
};

/*** End of the eventloop functions. ***/

/*** Conversation uiops ***/
static void received_im_msg(PurpleAccount *account, char *who, char *message, PurpleConversation *conv, PurpleMessageFlags flags)
{
	const char *name;
	if (who && *who)
		name = who;
	else
		name = NULL;
	char buf[4000];
	char pmess[2001];
	mysql_real_escape_string(conn,pmess,purple_markup_strip_html(message),strlen(purple_markup_strip_html(message)));
	sprintf(buf,gettext("SELECT user_id FROM kwippy_user_profile WHERE hash = '%s'"),pmess);
	syslog(LOG_LOCAL0, "code entered %s (%m)",pmess);
	if(mysql_ping(conn)!=0) {
		conn = mysql_init(NULL);
		if (!mysql_real_connect(conn, dbserver,dbuser, dbpassword, dbdatabase, 0, NULL, 0)) {
			exit(0);
		}
	}
	if(mysql_query(conn,buf)) {
	} else {
		int uid,aid;
		res = mysql_use_result(conn);
		int c=0;
		while ((row = mysql_fetch_row(res)) != NULL) {
			uid=atoi(row[0]);
			c++;
			//printf("uid : %s\n",row[0]);
		}
		mysql_free_result(res);
		// Write query to update accounts table
		if(c==1) {
			char * pch;
			pch = strtok (name,"/");
			serv_send_im(account->gc,who,"The code was correct. Welcome to Kwippy.",0);
			sprintf(buf,gettext("update kwippy_account set user_id=%d where provider_login ='%s' and provider=%s"),uid,pch,ppid);
			mysql_query(conn,buf);
			syslog(LOG_LOCAL0, "A user was found id : %d %s(%m)",uid,pch);
		} else {
			serv_send_im(account->gc,who,"did u copy the code correctly? you could also just click on the \"copy this code\" link.",0);
		}
	}
}
/* Mysql functions */
MYSQL *check_conn(MYSQL *conn_old) {
if(mysql_ping(conn_old)!=0) {
	MYSQL *new_conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, dbserver,dbuser, dbpassword, dbdatabase, 0, NULL, 0)) {
		exit(0);
	}
	return new_conn;
}
return conn_old;
}

MYSQL_RES *user_data(char *name,char *provider) {
	char buf[4000];
	sprintf(buf,"SELECT user_id,id FROM kwippy_account WHERE provider_login='%s' AND provider=%s",name,provider);
	mysql_query(conn,buf);
	MYSQL_RES *new_res = mysql_use_result(conn);
	return new_res;
}

static void node_update(PurpleBuddyList *list, PurpleBlistNode *node){
        if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
	char buf[4000];
	const GList *iter;
	const char *name = NULL;
	PurpleBuddy *buddy = (PurpleBuddy*)node;
	PurpleStatusPrimitive prim;
	PurplePresence *presence;
	PurpleStatus *now;
	PurpleAccount *account=buddy->account;
	presence = purple_buddy_get_presence(buddy);
	now = purple_presence_get_active_status(presence);
	prim = purple_status_type_get_primitive(purple_status_get_type(now));
	if(purple_status_get_attr_string(now,"message")!=NULL){
		int count=0;
		syslog(LOG_LOCAL0, "A quip came in from %s (%m)",buddy->name);
		
		if(node->ui_data == NULL) {
			syslog(LOG_LOCAL0, "buddy is null");
			struct gtuple *temp=(struct tuple *)malloc(sizeof(struct gtuple));		
			MYSQL_RES *new_res = user_data(buddy->name,ppid);
			while ((row = mysql_fetch_row(new_res)) != NULL) {
				temp->uid=atoi(row[0]);
				temp->aid=atoi(row[1]);
				count++;
				syslog(LOG_LOCAL0, "Found entry %s user_id:%s id:%s (%m)",buddy->name,row[0],row[1]);
			}
			mysql_free_result(new_res);

			if(count==0) {
				sprintf(buf,gettext("INSERT INTO kwippy_account(provider_login,provider,registration_type,status,created_at,user_id) VALUES('%s',%s,0,0,NOW(),-1)"),buddy->name,ppid);
				mysql_query(conn,buf);
				syslog(LOG_LOCAL0, "No account found creating entry for %s (%m)",buddy->name);
				sprintf(buf,"SELECT id FROM kwippy_account WHERE provider_login='%s' AND provider=%s",buddy->name,ppid);
				mysql_query(conn,buf);
				MYSQL_RES *new_res1 = mysql_use_result(conn);
				while ((row = mysql_fetch_row(new_res1)) != NULL) {
					temp->aid=atoi(row[0]);
					break;
				}
				mysql_free_result(new_res1);
				temp->uid=-1;
			}
			node->ui_data = temp;
			sprintf(buf,"SELECT original FROM kwippy_quip WHERE account_id = %d order by created_at desc limit 1",temp->aid);
			if(mysql_query(conn,buf)) {
			} else {
				MYSQL_RES *new_res2 = mysql_use_result(conn);
				strcpy(temp->hmd,"--null--");
				while ((row = mysql_fetch_row(new_res2)) != NULL) {
					strcpy(temp->hmd,row[0]);
				}
				mysql_free_result(new_res2);
			}
			
		}
		struct gtuple *temp = (struct gtuple *)node->ui_data;
		int same = strcmp(temp->hmd,purple_status_get_attr_string(now,"message"));
		if(same!=0) {
			sprintf(buf,gettext("INSERT INTO kwippy_quip(primitive_state,original,formated,created_at,account_id,is_filtered) VALUES('%s','%s','%s',NOW(),%d,0)"),purple_primitive_get_name_from_type(prim),purple_status_get_attr_string(now,"message"),purple_status_get_attr_string(now,"message"),temp->aid);
			mysql_query(conn,buf);
			syslog(LOG_LOCAL0, "Inserted quip");
		}
		strcpy(temp->hmd,purple_status_get_attr_string(now,"message"));
		syslog(LOG_LOCAL0, "Exited");
	}
	}
}

static PurpleBlistUiOps null_blist_uiops = {
        NULL,
        NULL,
        NULL,
        node_update,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL

};

static void * req_auth(PurpleAccount *account,
                        const char *remote_user,
                        const char *id,
                        const char *alias,
                        const char *message,
                        gboolean on_list,
                        PurpleAccountRequestAuthorizationCb auth_cb,
                        PurpleAccountRequestAuthorizationCb deny_cb,
                        void *user_data) {
	void *uihandle;
	//printf("Request to authorize : %s %s %s\n", remote_user, alias, message);
	PurpleBuddy *buddy;
	buddy = purple_buddy_new(account, remote_user, alias);
	purple_account_add_buddy(account, buddy);
	purple_blist_request_add_buddy(account,remote_user,NULL,alias);
	char buf[1000];
	sprintf(buf,gettext("INSERT INTO kwippy_account(provider_login,provider,registration_type,status,created_at,user_id) VALUES('%s',%s,0,1,NOW(),-1)"),remote_user,ppid);
	if(mysql_ping(conn)!=0) {
		conn = mysql_init(NULL);
		if (!mysql_real_connect(conn, dbserver,dbuser, dbpassword, dbdatabase, 0, NULL, 0)) {
			exit(0);
		}
	}
	mysql_query(conn,buf);
	syslog(LOG_LOCAL0, "%s was added(%m)",remote_user);
	serv_send_im(account->gc,remote_user,"hi, you can store your custom status messages. to begin storing, you would need to send a passcode. it's there in your dasboard>import.",0);
	auth_cb(user_data);
	return uihandle;
}
static PurpleAccountUiOps null_account_uiops = {
	NULL,
	NULL,
	NULL,
	req_auth,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
static void null_ui_init()
{
	purple_accounts_set_ui_ops(&null_account_uiops);
	purple_blist_set_ui_ops(&null_blist_uiops);
}
static PurpleCoreUiOps null_core_uiops = 
{
	NULL,
	NULL,
	null_ui_init,
	NULL,
	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_libpurple()
{
	purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
	purple_debug_set_enabled(FALSE);
	purple_core_set_ui_ops(&null_core_uiops);
	purple_eventloop_set_ui_ops(&glib_eventloops);
	purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);
	if (!purple_core_init(UI_ID)) {
		/* Initializing the core failed. Terminate. */
		fprintf(stderr,
				"libpurple initialization failed. Dumping core.\n"
				"Please report this!\n");
		abort();
	}

	/* Create and load the buddylist. */
	purple_set_blist(purple_blist_new());
	purple_blist_load();

	/* Load the preferences. */
	purple_prefs_load();

	/* Load the desired plugins. The client should save the list of loaded plugins in
	 * the preferences using purple_plugins_save_loaded(PLUGIN_SAVE_PREF) */
	purple_plugins_load_saved(PLUGIN_SAVE_PREF);

	/* Load the pounces. */
	purple_pounces_load();
}

static void
signed_on(PurpleConnection *gc, gpointer null)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	//printf("Account connected: %s %s\n", account->username, account->protocol_id);
}

static void
connect_to_signals()
{
	static int handle;
	purple_signal_connect(purple_connections_get_handle(), "signed-on", &handle,PURPLE_CALLBACK(signed_on), NULL);
	purple_signal_connect(purple_conversations_get_handle(), "received-im-msg", &handle ,PURPLE_CALLBACK(received_im_msg), NULL);
}

int main(int argc, char *argv[])
{

	#ifdef ENABLE_NLS
        bindtextdomain(PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(PACKAGE, "UTF-8");
	textdomain(PACKAGE);
	#endif
	#ifdef HAVE_SETLOCALE
	setlocale(LC_ALL, "");
	#endif
	
	if(argc!=2) {
		printf("Not enough arguments provided\n");
		exit(0);
	}
	errreport("Starting, reading configuration");
	FILE *confFile;
	confFile = fopen(argv[1],"r");
	if(fgets(dbserver, 80, confFile)==NULL) {
		exit(0);
	}
	dbserver[strlen(dbserver)-1]='\0';
	fgets(dbuser, 80, confFile);
	dbuser[strlen(dbuser)-1]='\0';
	fgets(dbpassword, 80, confFile);
	dbpassword[strlen(dbpassword)-1]='\0';
	fgets(dbdatabase, 80, confFile);
	dbdatabase[strlen(dbdatabase)-1]='\0';
	fgets(pname, 80, confFile);
	pname[strlen(pname)-1]='\0';
	fgets(puser, 80, confFile);
	puser[strlen(puser)-1]='\0';
	fgets(ppass, 80, confFile);
	ppass[strlen(ppass)-1]='\0';
	fgets(ppid,80,confFile);
	ppid[strlen(ppid)-1]='\0';
	fclose(confFile);
	/* Lets connect to the database for a start */
	conn = mysql_init(NULL);
	my_bool rt = 1;
	mysql_options(conn,MYSQL_OPT_RECONNECT , &rt);
	/* Connect to database */
	if (!mysql_real_connect(conn, dbserver,dbuser, dbpassword, dbdatabase, 0, NULL, 0)) {
	fprintf(stderr, "%s\n", mysql_error(conn));
	exit(0);
	}
	//printf("Connected to the database\n");
	
	GList *iter;
	int i, num;
	GList *names = NULL;
	const char *prpl;
	char name[128];
	char *password;
	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	PurpleAccount *account;
	PurpleSavedStatus *status;
	FILE *pidfile;
	char ppath[100];
	sprintf(ppath,"/var/log/kwippy/client%s.pid",ppid);
	pidfile = fopen(ppath,"w");
	pid = getpid();
	char pnum[100];
	sprintf(pnum,"%d",pid);
	fputs(pnum,pidfile);
	fclose(pidfile);
	
	signal(SIGCHLD, SIG_IGN);
	init_libpurple();

	//printf("libpurple initialized.\n");
	int count=0;
	iter = purple_plugins_get_protocols();
	for (i = 0; iter; iter = iter->next) {
		PurplePlugin *plugin = iter->data;
		PurplePluginInfo *info = plugin->info;
		if (info && info->name) {
			//printf("\t%d: %s\n", i++, info->name);
			names = g_list_append(names, info->id);
			if(strcmp(info->name,pname)==0) {
				num=count;
			}
			count++;
		}
	}
	//printf("Select the protocol [0-%d]: ", i-1);
	//fgets(name, sizeof(name), stdin);
	//sscanf(name, "%d", &num);
	//printf("%s %d\n",pname,count);
	//num=12;
	prpl = g_list_nth_data(names, num);

	//printf("Username: ");
	//fgets(name, sizeof(name), stdin);
	//name[strlen(name) - 1] = 0;  /* strip the \n at the end */

	/* Create the account */
	account = purple_account_new(puser, prpl);

	/* Get the password for the account */
	//password = getpass("Password: ");
	purple_account_set_password(account,ppass);
	if(strcmp(ppid,"2")==0) {
		purple_account_set_string(account,"connect_server","talk.google.com");
	}
	/* It's necessary to enable the account first. */
	purple_account_set_enabled(account, UI_ID, TRUE);

	/* Now, to connect the account(s), create a status and activate it. */
	status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
	purple_savedstatus_set_message(status,"i'll store all your statuses :)");
	purple_savedstatus_activate(status);

	connect_to_signals();

	g_main_loop_run(loop);

	return 0;
}