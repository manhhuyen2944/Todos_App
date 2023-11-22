using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using Todos_App.Models;

namespace Todos_App.ViewModel
{
    [BindProperties]
    public class FilterRequest
    {
        [BindProperty(Name = "keyword")]
        public string Keyword { get; set; }
    }
}
