    1 /*
    2  *   This program is is free software; you can redistribute it and/or modify
    3  *   it under the terms of the GNU General Public License as published by
    4  *   the Free Software Foundation; either version 2 of the License, or (at
    5  *   your option) any later version.
    6  *
    7  *   This program is distributed in the hope that it will be useful,
    8  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
    9  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   10  *   GNU General Public License for more details.
   11  *
   12  *   You should have received a copy of the GNU General Public License
   13  *   along with this program; if not, write to the Free Software
   14  *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
   15  */
   16 
   17 /*
   18  * $Id: 9893ce9add36d566546e1c0b1be509e02366167a $
   19  * @file rlm_cb_mfa.c
   20  * @brief Example module code.
   21  *
   22  * @copyright 2013 The FreeRADIUS server project
   23  * @copyright 2013 Khurshid Alam <khurshid.alam@dfki.de>
   24  */
   25 RCSID("$Id: 9893ce9add36d566546e1c0b1be509e02366167a $")
   26 
   27 #include <freeradius-devel/radiusd.h>
   28 #include <freeradius-devel/modules.h>
   29 #include <freeradius-devel/rad_assert.h>
   30 
   31 /*
   32  *      Define a structure for our module configuration.
   33  *
   34  *      These variables do not need to be in a structure, but it's
   35  *      a lot cleaner to do so, and a pointer to the structure can
   36  *      be used as the instance handle.
   37  */
   38 typedef struct rlm_cb_mfa_t {
   39         bool            boolean;
   40         uint32_t        value;
   41         char const      *string;
   42         fr_ipaddr_t     ipaddr;
   43 } rlm_cb_mfa_t;
   44 
   45 /*
   46  *      A mapping of configuration file names to internal variables.
   47  */
   48 static const CONF_PARSER module_config[] = {
   49         { FR_CONF_OFFSET("integer", PW_TYPE_INTEGER, rlm_cb_mfa_t, value), .dflt = "1" },
   50         { FR_CONF_OFFSET("boolean", PW_TYPE_BOOLEAN, rlm_cb_mfa_t, boolean), .dflt = "no" },
   51         { FR_CONF_OFFSET("string", PW_TYPE_STRING, rlm_cb_mfa_t, string) },
   52         { FR_CONF_OFFSET("ipaddr", PW_TYPE_IPV4_ADDR, rlm_cb_mfa_t, ipaddr), .dflt = "*" },
   53         CONF_PARSER_TERMINATOR
   54 };
   55 
   56 static int rlm_cb_mfa_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
   57                            UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
   58 {
   59         rad_assert(check->da->type == PW_TYPE_STRING);
   60 
   61         RINFO("Example-Paircmp called with \"%s\"", check->vp_strvalue);
   62 
   63         if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
   64         return 1;
   65 }
   66 
   67 /*
   68  *      Do any per-module initialization that is separate to each
   69  *      configured instance of the module.  e.g. set up connections
   70  *      to external databases, read configuration files, set up
   71  *      dictionary entries, etc.
   72  */
   73 static int mod_instantiate(CONF_SECTION *conf, void *instance)
   74 {
   75         rlm_cb_mfa_t *inst = instance;
   76 
   77         /*
   78          *      Do more work here
   79          */
   80         if (!inst->boolean) {
   81                 cf_log_err_cs(conf, "Boolean is false: forcing error!");
   82                 return -1;
   83         }
   84 
   85         paircompare_register_byname("Example-Paircmp", fr_dict_attr_by_num(NULL, 0, PW_USER_NAME), false,
   86                                     rlm_cb_mfa_cmp, inst);
   87 
   88         return 0;
   89 }
   90 
   91 /*
   92  *      Find the named user in this modules database.  Create the set
   93  *      of attribute-value pairs to check and reply with for this user
   94  *      from the database. The authentication code only needs to check
   95  *      the password, the rest is done here.
   96  */
   97 static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
   98 {
   99         VALUE_PAIR *state;
  100 
  101         /*
  102          *  Look for the 'state' attribute.
  103          */
  104         state = fr_pair_find_by_num(request->packet->vps, 0, PW_STATE, TAG_ANY);
  105         if (state != NULL) {
  106                 RDEBUG("Found reply to access challenge");
  107                 return RLM_MODULE_OK;
  108         }
  109 		char ip_begin[] = "10.0.0.001";
	char ip_end[] = "10.0.0.100";

	char buffer[INET_ADDRSTRLEN];
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_num(request->packet->vps, 0, PW_FRAMED_IP_ADDRESS, TAG_ANY);
	if (vp){
	
		inet_netop(AF_INET, &vp->vp_ipaddr, buffer, sizeof(buffer));
		
		if(memcmp(&buffer, &ip_begin, sizeof(buffer)) >= 0 && memcmp(&buffer, &ip_end, sizeof(buffer)) <=0)){

			time_t c_time;
			time(&c_time);
			struct tm *t_current;
			t_current = localtime(&c_time);

			char buffer[80];
			strftime(buffer, sizeof(buffer), "%H:%M:%S", t_current);

			std::string start_hr = "08:00:00", end_hr = "18:00:00";
			

			if(((std::string)buffer < end_hr) && ((std::string)buffer > start_hr))
			//MOD_OK and log the info
			else //challange and log_time;		
		} 
		else {

			//MOD_Challange_Enable
		}
		

	}	
		
		
  110         /*
  111          *  Create the challenge, and add it to the reply.
  112          */
  113         pair_make_reply("Reply-Message", "This is a challenge", T_OP_EQ);
  114         pair_make_reply("State", "0", T_OP_EQ);
  115 
  116         /*
  117          *  Mark the packet as an Access-Challenge packet.
  118          *
  119          *  The server will take care of sending it to the user.
  120          */
  121         request->reply->code = PW_CODE_ACCESS_CHALLENGE;
  122         RDEBUG("Sending Access-Challenge");
  123 
  124         return RLM_MODULE_HANDLED;
  125 }
  126 
  127 /*
  128  *      Authenticate the user with the given password.
  129  */
  130 static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED REQUEST *request)
  131 {
	  
	  
  132         return RLM_MODULE_OK;
  133 }
  134 
  135 #ifdef WITH_ACCOUNTING
  136 /*
  137  *      Massage the request before recording it or proxying it
  138  */
  139 static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED REQUEST *request)
  140 {
  141         return RLM_MODULE_OK;
  142 }
  143 
  144 /*
  145  *      Write accounting information to this modules database.
  146  */
  147 static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
  148 {
  149         return RLM_MODULE_OK;
  150 }
  151 
  152 /*
  153  *      See if a user is already logged in. Sets request->simul_count to the
  154  *      current session count for this user and sets request->simul_mpp to 2
  155  *      if it looks like a multilink attempt based on the requested IP
  156  *      address, otherwise leaves request->simul_mpp alone.
  157  *
  158  *      Check twice. If on the first pass the user exceeds his
  159  *      max. number of logins, do a second pass and validate all
  160  *      logins by querying the terminal server (using eg. SNMP).
  161  */
  162 static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, REQUEST *request)
  163 {
  164         request->simul_count=0;
  165 
  166         return RLM_MODULE_OK;
  167 }
  168 #endif
  169 
  170 
  171 /*
  172  *      Only free memory we allocated.  The strings allocated via
  173  *      cf_section_parse() do not need to be freed.
  174  */
  175 static int mod_detach(UNUSED void *instance)
  176 {
  177         /* free things here */
  178         return 0;
  179 }
  180 
  181 /*
  182  *      The module name should be the only globally exported symbol.
  183  *      That is, everything else should be 'static'.
  184  *
  185  *      If the module needs to temporarily modify it's instantiation
  186  *      data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
  187  *      The server will then take care of ensuring that the module
  188  *      is single-threaded.
  189  */
  190 extern module_t rlm_cb_mfa;
  191 module_t rlm_cb_mfa = {
  192         .magic          = RLM_MODULE_INIT,
  193         .name           = "cb_mfa",
  194         .type           = RLM_TYPE_THREAD_SAFE,
  195         .inst_size      = sizeof(rlm_cb_mfa_t),
  196         .config         = module_config,
  197         .instantiate    = mod_instantiate,
  198         .detach         = mod_detach,
  199         .methods = {
  200                 [MOD_AUTHENTICATE]      = mod_authenticate,
  201                 [MOD_AUTHORIZE]         = mod_authorize,
  202 #ifdef WITH_ACCOUNTING
  203                 [MOD_PREACCT]           = mod_preacct,
  204                 [MOD_ACCOUNTING]        = mod_accounting,
  205                 [MOD_SESSION]           = mod_checksimul
  206 #endif
  207         },
  208 };

