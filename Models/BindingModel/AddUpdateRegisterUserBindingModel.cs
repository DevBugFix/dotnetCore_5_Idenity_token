
using System.Collections.Generic;

namespace Models.BindingModel
{


    public class AddUpdateRegisterUserBindingModel
    {

        public string FullName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public List<string> Roles { get; set; }
    }
}