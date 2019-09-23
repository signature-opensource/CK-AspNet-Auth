using CK.Text;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CodeCake
{
    public class AngularWorkspace : NPMProjectContainer
    {
        public NPMProject WorkspaceProject { get; }
        public IReadOnlyList<NPMProject> Projects { get; }
        public NormalizedPath OutputPath { get; }

        AngularWorkspace(
            NPMProject workspaceProject,
            IReadOnlyList<NPMProject> projects,
            NormalizedPath outputPath )
            :base()
        {
            WorkspaceProject = workspaceProject;
            Projects = projects;
            OutputPath = outputPath;
        }
        public void Build() => WorkspaceProject.RunBuild();

        public static AngularWorkspace Create( StandardGlobalInfo globalInfo, NPMSolution npmSolution, NormalizedPath path, NormalizedPath outputPath )
        {
            NormalizedPath packageJsonPath = path.AppendPart( "package.json" );
            NormalizedPath angularJsonPath = path.AppendPart( "angular.json" );

            JObject packageJson = JObject.Parse( File.ReadAllText( packageJsonPath ) );
            JObject angularJson = JObject.Parse( File.ReadAllText( angularJsonPath ) );
            if( !angularJson["private"].ToObject<bool>() ) throw new InvalidDataException( "A workspace project should be private." );
            string solutionName = packageJson["name"].ToString();
            List<string> names = angularJson["projects"].ToObject<JObject>().Properties().Select( p => p.Name ).ToList();
            List<NPMProject> projects = names.Select(
                p => NPMPublishedProject.Create(
                    globalInfo,
                    npmSolution,
                    new NormalizedPath( angularJson["projects"][p]["root"].ToString() ),
                    outputPath.AppendPart( p )
                )
            ).ToList();
            var output = new AngularWorkspace( projects.Single( p => p.DirectoryPath == path ), projects, outputPath );
            npmSolution.Add( output );
            return output;
        }
    }
}
